"""No-socket scheduling proof of unmodified mitmproxy ConnectionHandler methods.

The scheduler uses real BaseEventLoop ready Handles and real asyncio.Tasks but
never runs an I/O reactor or creates a selector/self-pipe. This is model evidence,
not real runtime/network evidence. No dependency methods are monkeypatched.
"""
from __future__ import annotations
import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import sys
import unittest

import h2.config
import h2.connection
from mitmproxy import connection, http
from mitmproxy.addons.proxyserver import Proxyserver
from mitmproxy.proxy import events, server, server_hooks
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers import http as layers
from proof_upstream import opts, association, ProbeServer

RESULTS=[]
SOCKET_AUDITS=[]

def forbid_socket_creation(event, args):
    if event == 'socket.__new__':
        SOCKET_AUDITS.append(event)
        raise AssertionError('Socket creation forbidden in pure scheduling proof')

sys.addaudithook(forbid_socket_creation)


class ReadyScheduler:
    def __init__(self, loop_type=asyncio.BaseEventLoop):
        # BaseEventLoop creates no selector, wakeup socket, or I/O transport.
        self.loop=loop_type()
        self.errors=[]
        self.loop.set_exception_handler(lambda loop,context:self.errors.append(context))
        self.previous=asyncio.events._get_running_loop()
        asyncio.events._set_running_loop(self.loop)

    def one(self):
        if self.loop._ready:
            self.loop._ready.popleft()._run()
            assert not self.errors,self.errors
            return True
        return False

    def ready(self):
        budget=1000
        while self.one():
            budget-=1
            assert budget>0,'Unexpected busy loop'

    def now(self,coro):
        # server_event contains no await after its unblocked lock acquisition.
        try:
            value=coro.send(None)
        except StopIteration as stop:
            return stop.value
        else:
            coro.close()
            raise AssertionError(f'Unexpected async suspension: {value!r}')

    def close(self):
        for task in asyncio.all_tasks(self.loop):task.cancel()
        self.ready()
        assert not asyncio.all_tasks(self.loop)
        self.loop.close()
        asyncio.events._set_running_loop(self.previous)


class ClientMemoryWriter:
    def __init__(self,peer):
        self.peer=peer
        self.closed=False
        self.bytes=0
    def is_closing(self):return self.closed
    def write(self,data):
        self.bytes+=len(data)
        self.peer.receive_data(data)
    def close(self):self.closed=True


class Handler(server.ConnectionHandler):
    def __init__(self,context,gate):
        super().__init__(context)
        self.hooks=[]
        self.hook_gate=gate
        self.flows={}
    async def handle_hook(self,hook):
        self.hooks.append(hook.name)
        if isinstance(hook,layers.HttpRequestHeadersHook):
            f=hook.flow
            f.request.stream=True
            self.flows[int(f.request.path.strip('/'))]=f
        if isinstance(hook,server_hooks.ServerConnectHook) and self.hook_gate is not None:
            await self.hook_gate
        if isinstance(hook,server_hooks.ServerConnectedHook) and getattr(self,'connected_gate',None) is not None:
            await self.connected_gate
    def log(self,*args,**kwargs):pass


class SyntheticTransport(asyncio.Transport):
    """Test transport supplied by a test event loop. No socket or real I/O."""
    def __init__(self,loop,protocol):
        self.loop=loop;self.protocol=protocol;self.closing=False;self.sent=[]
    def get_extra_info(self,name,default=None):
        return {'peername':('127.0.0.1',443),'sockname':('127.0.0.1',50001)}.get(name,default)
    def is_closing(self):return self.closing
    def write(self,data):self.sent.append(data)
    def close(self):
        self.closing=True
        self.loop.call_soon(self.protocol.connection_lost,None)
    def abort(self):self.close()


class MemoryConnectLoop(asyncio.BaseEventLoop):
    """Supported asyncio loop implementation for deterministic synthetic connect."""
    async def create_connection(self,protocol_factory,*args,**kwargs):
        protocol=protocol_factory()
        transport=SyntheticTransport(self,protocol)
        protocol.connection_made(transport)
        return transport,protocol


def confirmed_terminal(handler,conn,task,captured_io,*,disconnected=False):
    """Conservative test-only terminal predicate; never trust stale opening IO."""
    if not task.done():return False
    current=handler.transports.get(conn)
    if current is not None and current.handler is not task:return False
    io=current if current is not None else captured_io
    if io.writer is None:
        return (task.cancelled() and conn.timestamp_tcp_setup is None
                and conn.state is connection.ConnectionState.CLOSED)
    return (disconnected and current is None and io.writer.is_closing()
            and conn.state is connection.ConnectionState.CLOSED)


class Proof(unittest.TestCase):
    def test_actual_owned_pending_tasks_done_in_three_cancel_windows(self):
        for when in ('before_start','server_connect_hook','semaphore'):
            with self.subTest(when=when):
                sched=ReadyScheduler()
                try:
                    ctx=Context(connection.Client(peername=('127.0.0.1',50000),
                                                  sockname=('127.0.0.1',443),
                                                  state=connection.ConnectionState.OPEN),opts())
                    ctx.client.alpn=b'h2';ctx.client.tls=True;ctx.client.sni='example.test'
                    ctx.server.address=('example.test',443);ctx.server.tls=True
                    gate=sched.loop.create_future() if when=='server_connect_hook' else None
                    handler=Handler(ctx,gate)
                    # Handler owns the real protocol layer under test.
                    root=layers.HttpLayer(ctx,layers.HTTPMode.transparent)
                    handler.layer=root
                    probe=ProbeServer(ctx.fork())
                    root.connections.setdefault(ctx.client,probe)
                    peer=h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
                    peer.initiate_connection()
                    client_wait=sched.loop.create_future()
                    async def hold_client():await client_wait
                    client_task=sched.loop.create_task(hold_client())
                    writer=ClientMemoryWriter(peer)
                    handler.transports[ctx.client]=server.ConnectionIO(handler=client_task,writer=writer)
                    proxyserver=Proxyserver()
                    with proxyserver.register_connection(ctx.client.id,handler):
                        sched.now(handler.server_event(events.Start()))
                        sched.now(handler.server_event(events.DataReceived(ctx.client,peer.data_to_send())))
                        peer.send_headers(1,[(':method','POST'),(':scheme','https'),
                                             (':authority','example.test'),(':path','/1')],end_stream=False)
                        sched.now(handler.server_event(events.DataReceived(ctx.client,peer.data_to_send())))
                        # Execute real hook Tasks until server_event installs the real
                        # OpenConnection task, stopping before its first scheduled step.
                        while len(handler.transports)<2:
                            self.assertTrue(sched.one())
                        flow=handler.flows[1]
                        owned=association(root,flow,1)
                        conn=owned['connection']
                        self.assertIs(proxyserver.connections[ctx.client.id],handler)
                        self.assertIs(handler.client,ctx.client)
                        self.assertIs(handler.layer,root)
                        self.assertIs(root.connections[conn],owned['owner'])
                        captured_io=handler.transports[conn]
                        task=captured_io.handler
                        self.assertIsInstance(task,asyncio.Task)
                        self.assertFalse(task.done())
                        self.assertIsNone(handler.transports[conn].writer)
                        if when=='semaphore':
                            sem=handler.max_conns[conn.address]
                            for _ in range(5):self.assertTrue(sched.now(sem.acquire()))
                        if when!='before_start':sched.ready()
                        if when=='before_start':self.assertNotIn('server_connect',handler.hooks)
                        else:self.assertIn('server_connect',handler.hooks)
                        self.assertFalse(task.done())
                        done=[]
                        # This is the proposed READ-ONLY transport completion observer.
                        # Capture verified exact task before issuing ordinary close.
                        task.add_done_callback(lambda t:done.append(dict(
                            same_task=t is task,done=t.done(),cancelled=t.cancelled(),
                            writer_absent=handler.transports[conn].writer is None)))
                        probe.close_request=(root,flow,1)
                        # Actual ProbeServer -> HttpLayer -> ConnectionHandler.server_event
                        # -> close_connection; no direct Task.cancel in test action.
                        sched.now(handler.server_event(events.DataReceived(ctx.client,b'')))
                        self.assertEqual(conn.state,connection.ConnectionState.CLOSED)
                        sched.ready()
                        self.assertEqual(done,[dict(same_task=True,done=True,cancelled=True,writer_absent=True)])
                        self.assertTrue(confirmed_terminal(handler,conn,task,captured_io))
                        self.assertNotIn('server_connect_error',handler.hooks)
                        self.assertNotIn('server_disconnected',handler.hooks)
                        self.assertTrue(root.waiting_for_establishment)
                        self.assertTrue(owned['owner']._paused)
                        self.assertIsNone(handler.transports[conn].writer)
                        # The dependency cannot finish this layer by a callback it
                        # never emits. Its buffers remain untouched, but its sole
                        # owned opening task is now provably terminal without a writer.
                        RESULTS.append(dict(case=when, task_observer=done[0],
                                            hooks=handler.hooks,
                                            pending_layer_commands_remain=True,
                                            upstream_connection_closed=True,
                                            server_event_and_close_connection_unmodified=True,
                                            socket_attempts=len(SOCKET_AUDITS)))
                finally:sched.close()
        self.assertEqual(SOCKET_AUDITS,[])


    def test_negative_cancel_inside_server_connected_leaves_writer_open(self):
        sched=ReadyScheduler(MemoryConnectLoop)
        try:
            ctx=Context(connection.Client(peername=('127.0.0.1',50000),
                                          sockname=('127.0.0.1',443),
                                          state=connection.ConnectionState.OPEN),opts())
            ctx.client.alpn=b'h2';ctx.client.tls=True;ctx.client.sni='example.test'
            ctx.server.address=('example.test',443);ctx.server.tls=True
            handler=Handler(ctx,None)
            handler.connected_gate=sched.loop.create_future()
            root=layers.HttpLayer(ctx,layers.HTTPMode.transparent);handler.layer=root
            probe=ProbeServer(ctx.fork());root.connections.setdefault(ctx.client,probe)
            peer=h2.connection.H2Connection(h2.config.H2Configuration(client_side=True));peer.initiate_connection()
            client_wait=sched.loop.create_future()
            async def hold_client():await client_wait
            handler.transports[ctx.client]=server.ConnectionIO(
                handler=sched.loop.create_task(hold_client()),writer=ClientMemoryWriter(peer))
            sched.now(handler.server_event(events.Start()))
            sched.now(handler.server_event(events.DataReceived(ctx.client,peer.data_to_send())))
            peer.send_headers(1,[(':method','POST'),(':scheme','https'),
                                 (':authority','example.test'),(':path','/1')],end_stream=False)
            sched.now(handler.server_event(events.DataReceived(ctx.client,peer.data_to_send())))
            while len(handler.transports)<2:self.assertTrue(sched.one())
            flow=handler.flows[1];owned=association(root,flow,1);conn=owned['connection']
            opening_io=handler.transports[conn];task=opening_io.handler
            self.assertIsNone(opening_io.writer)
            sched.ready()
            self.assertIn('server_connected',handler.hooks)
            current_io=handler.transports[conn]
            self.assertIsNot(current_io,opening_io)
            self.assertIs(current_io.handler,task)
            self.assertIsInstance(current_io.writer,asyncio.StreamWriter)
            self.assertFalse(current_io.writer.is_closing())
            self.assertFalse(task.done())
            callbacks=[];task.add_done_callback(lambda t:callbacks.append(t))
            probe.close_request=(root,flow,1)
            sched.now(handler.server_event(events.DataReceived(ctx.client,b'')))
            sched.ready()
            self.assertTrue(task.done());self.assertTrue(task.cancelled())
            self.assertEqual(callbacks,[task])
            self.assertEqual(conn.state,connection.ConnectionState.CLOSED)
            self.assertFalse(current_io.writer.is_closing())
            self.assertIs(handler.transports[conn],current_io)
            self.assertNotIn('server_disconnected',handler.hooks)
            self.assertNotIn('server_connect_error',handler.hooks)
            self.assertFalse(confirmed_terminal(handler,conn,task,opening_io))
            self.assertTrue(root.waiting_for_establishment)
            # Repeating the ONLY approved close operation cancels a completed task;
            # it does not reach the StreamWriter or remove its transport entry.
            probe.close_request=(root,flow,1)
            sched.now(handler.server_event(events.DataReceived(ctx.client,b'')));sched.ready()
            self.assertFalse(current_io.writer.is_closing())
            self.assertIs(handler.transports[conn],current_io)
            RESULTS.append(dict(case='negative_server_connected_wait',
                                actual_open_connection_and_stream_writer=True,
                                transport_kind='synthetic asyncio.Transport; no socket',
                                task_done=True,task_cancelled=True,
                                opening_io_replaced=True,opening_io_writer_absent=True,
                                current_io_writer_open=True,transport_still_registered=True,
                                server_disconnected_hook=False,
                                repeated_normal_close_recovers=False,
                                terminal_predicate=False,p0_stop=True,
                                socket_attempts=len(SOCKET_AUDITS)))
            # Test cleanup only: the synthetic transport must be closed directly.
            # This is NOT counted as an approved production recovery or gate pass.
            current_io.writer.close();sched.ready()
        finally:sched.close()


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Proof))
    Path(__file__).with_name('pending_task_results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
    raise SystemExit(not result.wasSuccessful())
