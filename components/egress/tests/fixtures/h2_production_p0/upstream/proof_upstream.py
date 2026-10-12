"""Pure-layer pinned-dependency proof. No sockets; no dependency state patches."""
from __future__ import annotations
import collections
import hashlib
import importlib.metadata
import json
from pathlib import Path
import unittest
from typing import Optional
import h2.config
import h2.connection
import h2.events
import h2.settings
from mitmproxy import connection, http
from mitmproxy.options import Options
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers import http as layers
from mitmproxy.proxy.layers.http._http2 import Http2Client, Http2Server

REPORT = []


class ProbeServer(Http2Server):
    """Test-only concrete server owner. No override/patch of dependency classes."""
    def __init__(self, context):
        super().__init__(context)
        self.close_request = None
        self.wakeup = None
        self.callback_events = []

    def handle_event(self, event):
        # Outer hook survives base close_connection replacing _handle_event with done.
        self.callback_events.append(type(event).__name__)
        yield from super().handle_event(event)
        if self.close_request is not None:
            root, flow, client_id = self.close_request
            self.close_request = None
            owned = association(root, flow, client_id)
            assert root.connections[owned['connection']] is owned['owner']
            for target in (self.context.client, owned['connection']):
                yield commands.CloseConnection(target)
            self.wakeup = commands.RequestWakeup(0.01)
            yield self.wakeup


def opts():
    x = Options(http2_ping_keepalive=0)
    for name, typ, default in [
        ('validate_inbound_headers', bool, True),
        ('normalize_outbound_headers', bool, True),
        ('stream_large_bodies', Optional[str], None),
        ('body_size_limit', Optional[str], None),
        ('connection_strategy', str, 'lazy'),
        ('keep_host_header', bool, False),
    ]:
        x.add_option(name, typ, default, 'Pure layer proof option')
    return x


def descend(owner):
    """Observe only the concrete child chain, rejecting a cycle."""
    seen = set()
    while owner is not None:
        assert id(owner) not in seen
        seen.add(id(owner))
        yield owner
        owner = getattr(owner, 'child_layer', None)


def association(root, flow, client_id):
    """Test-only read-only association. Pending establishment uses real command sources."""
    # While GetHttpConnection is paused, flow.server_conn still points to the
    # original context.server. That object may even own a dead old H2 child.
    # The exact pending command identity must therefore take precedence.
    matches = []
    for conn, waiting in root.waiting_for_establishment.items():
        for cmd in waiting:
            stream = root.command_sources.get(cmd)
            if (isinstance(stream, layers.HttpStream)
                    and stream.flow is flow and stream.stream_id == client_id):
                matches.append((conn, root.connections.get(conn)))
    if len(matches) > 1:
        raise AssertionError(f'Association is not unique: {len(matches)} pending matches')
    if matches:
        conn, owner = matches[0]
        assert owner is not None
        chain = list(descend(owner))
        clients = [x for x in chain if isinstance(x, layers.HttpClient)]
        assert len(clients) == 1 and clients[0].context.server is conn
        return dict(kind='connecting', connection=conn, owner=owner,
                    child=None, ours=None)
    owner = root.connections.get(flow.server_conn)
    if owner is not None:
        chain = list(descend(owner))
        candidates = [x for x in chain if isinstance(x, Http2Client)]
        if len(candidates) == 1:
            child = candidates[0]
            assert child.conn is flow.server_conn
            ours = child.our_stream_id.get(client_id)
            queued = client_id in child.stream_queue
            assert not (ours is not None and queued)
            if ours is not None:
                assert child.their_stream_id[ours] == client_id
            return dict(kind='queued' if queued else 'mapped' if ours else 'pre-send',
                        connection=flow.server_conn, owner=owner, child=child,
                        ours=ours)
    raise AssertionError('No unique owned upstream association')


class Harness:
    def __init__(self, *, connected=True, upstream_tls=True,
                 max_streams=100, initial_window=65535, hold=(), probe=False):
        client = connection.Client(peername=('127.0.0.1', 50000),
                                   sockname=('127.0.0.1', 443),
                                   state=connection.ConnectionState.OPEN)
        client.alpn = b'h2'
        client.tls = True
        client.sni = 'example.test'
        self.ctx = Context(client, opts())
        self.ctx.server.address = ('example.test', 443)
        self.ctx.server.alpn = b'h2' if connected else None
        self.ctx.server.tls = upstream_tls
        self.ctx.server.state = (connection.ConnectionState.OPEN if connected
                                  else connection.ConnectionState.CLOSED)
        self.root = layers.HttpLayer(self.ctx, layers.HTTPMode.transparent)
        if probe:
            self.probe = ProbeServer(self.ctx.fork())
            self.root.connections.setdefault(self.ctx.client, self.probe)
        self.client = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        self.client.initiate_connection()
        self.origin = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
        self.origin.local_settings.max_concurrent_streams = max_streams
        self.origin.local_settings.initial_window_size = initial_window
        self.origin.local_settings.acknowledge()
        self.origin.initiate_connection()
        self.flows = {}
        self.hold = set(hold)
        self.held = {}
        self.opens = []
        self.out = []
        self.peer_events = {'client': [], 'origin': []}
        self.upstream_conn = None
        self.run(events.Start())
        self.from_client()

    def run(self, ev):
        pending = collections.deque([ev])
        while pending:
            event = pending.popleft()
            output = list(self.root.handle_event(event))
            for cmd in output:
                self.out.append(cmd)
                if isinstance(cmd, commands.StartHook):
                    f = cmd.args()[0]
                    if isinstance(f, http.HTTPFlow):
                        sid = int(f.request.path.split('/')[-1])
                        self.flows[sid] = f
                        if isinstance(cmd, layers.HttpRequestHeadersHook):
                            f.request.stream = True
                        key = (cmd.name, sid)
                    else:
                        key = (cmd.name, None)
                    if key in self.hold:
                        self.held[key] = cmd
                    else:
                        pending.append(events.HookCompleted(cmd))
                elif isinstance(cmd, commands.OpenConnection):
                    self.opens.append(cmd)
                elif isinstance(cmd, commands.SendData):
                    name = 'client' if cmd.connection is self.ctx.client else 'origin'
                    if name == 'origin':
                        self.upstream_conn = cmd.connection
                    peer = self.client if name == 'client' else self.origin
                    self.peer_events[name].extend(peer.receive_data(cmd.data))
                elif isinstance(cmd, (commands.CloseConnection, commands.Log,
                                      commands.RequestWakeup)):
                    pass
                else:
                    raise AssertionError(f'Unexpected outer command {cmd!r}')
        return output

    def release(self, key):
        self.hold.discard(key)
        self.run(events.HookCompleted(self.held.pop(key)))

    def from_client(self):
        data = self.client.data_to_send()
        if data:
            self.run(events.DataReceived(self.ctx.client, data))

    def from_origin(self):
        assert self.upstream_conn is not None
        data = self.origin.data_to_send()
        if data:
            self.run(events.DataReceived(self.upstream_conn, data))

    def headers(self, sid, *, end=False):
        self.client.send_headers(sid, [(':method', 'POST'), (':scheme', 'https'),
                                      (':authority', 'example.test'), (':path', f'/{sid}')],
                                 end_stream=end)
        self.from_client()

    def data(self, sid, data, *, end=False):
        self.client.send_data(sid, data, end_stream=end)
        self.from_client()

    def reset(self, sid):
        self.client.reset_stream(sid, error_code=8)
        self.from_client()

    def response(self, ours, *, end=True):
        self.origin.send_headers(ours, [(':status', '200')], end_stream=end)
        self.from_origin()

    def assoc(self, sid):
        return association(self.root, self.flows[sid], sid)

    def inspect(self, sid):
        a = self.assoc(sid)
        child, ours = a['child'], a['ours']
        stream = self.root.streams.get(sid)
        return dict(client_id=sid, kind=a['kind'], upstream_id=ours,
                    flow_points_at_owned_connection=self.flows[sid].server_conn is a['connection'],
                    chain=[type(x).__name__ for x in descend(a['owner'])],
                    root_stream_present=stream is not None,
                    client_state=stream.client_state.__name__ if stream else None,
                    server_state=stream.server_state.__name__ if stream else None,
                    upstream_layer_done=(child._handle_event == child.done) if child else None,
                    upstream_streams=list(child.streams) if child else None,
                    queue={str(k):[type(x).__name__ for x in v]
                           for k,v in child.stream_queue.items()} if child else None,
                    upload_buffers={str(k):sum(len(x.data) for x in v)
                                    for k,v in child.h2_conn.stream_buffers.items()} if child else None,
                    upload_trailers=list(child.h2_conn.stream_trailers) if child else None,
                    h2_state=child.h2_conn.streams[ours].state_machine.state.name
                             if child and ours in child.h2_conn.streams else None)

    def close_commands(self, sid):
        """Adapter-equivalent commands, with read-only exact ownership check."""
        a = self.assoc(sid)
        assert a['owner'] is self.root.connections[a['connection']]
        result = [commands.CloseConnection(self.ctx.client),
                  commands.CloseConnection(a['connection'])]
        self.out.extend(result)
        return result

    def closed_callback(self, conn):
        # Model outer transport acknowledging a full close; no socket is created.
        conn.state = connection.ConnectionState.CLOSED
        self.run(events.ConnectionClosed(conn))


class Proof(unittest.TestCase):
    def test_dependency_versions(self):
        actual = {x:importlib.metadata.version(x) for x in ('mitmproxy','h2','hyperframe')}
        self.assertEqual(actual, dict(mitmproxy='11.0.2',h2='4.1.0',hyperframe='6.0.1'))
        REPORT.append(dict(case='versions', actual=actual))

    def test_id_reorder_uses_owned_child_mapping(self):
        h = Harness(hold={('requestheaders',1)})
        h.headers(1)
        h.headers(3)
        h.from_origin()
        h.release(('requestheaders',1))
        self.assertEqual(h.assoc(3)['ours'],1)
        self.assertEqual(h.assoc(1)['ours'],3)
        self.assertIs(h.assoc(3)['child'],h.assoc(1)['child'])
        self.assertEqual([e.stream_id for e in h.peer_events['origin']
                          if isinstance(e,h2.events.RequestReceived)], [1,3])
        REPORT.append(dict(case='reorder', states=[h.inspect(1),h.inspect(3)]))

    def test_concurrency_queue_is_client_id_keyed(self):
        h = Harness(max_streams=1)
        h.headers(1)
        h.from_origin()
        h.headers(3)
        h.data(3,b'queued body')
        self.assertEqual(h.assoc(3)['kind'],'queued')
        self.assertIsNone(h.assoc(3)['ours'])
        self.assertEqual([e.stream_id for e in h.peer_events['origin']
                          if isinstance(e,h2.events.RequestReceived)], [1])
        REPORT.append(dict(case='concurrency_queue', state=h.inspect(3)))

    def test_early_response_not_upload_completion(self):
        h = Harness(initial_window=0)
        h.headers(1)
        h.from_origin()
        h.data(1,b'unwritten upload')
        h.response(1)
        a=h.assoc(1)
        self.assertEqual(h.root.streams[1].server_state.__name__,'state_done')
        self.assertEqual(h.root.streams[1].client_state.__name__,'state_stream_request_body')
        self.assertTrue(a['child'].h2_conn.stream_buffers[1])
        self.assertEqual(a['child'].h2_conn.streams[1].state_machine.state.name,'HALF_CLOSED_REMOTE')
        REPORT.append(dict(case='early_response_pending_upload',state=h.inspect(1)))

    def test_early_response_reset_orphan_and_both_close_orders(self):
        for upstream_first in (False,True):
            with self.subTest(upstream_first=upstream_first):
                h = Harness(initial_window=0,max_streams=1)
                h.headers(1); h.from_origin(); h.data(1,b'orphan upload')
                h.headers(3); h.data(3,b'queued sibling')
                h.response(1)
                h.reset(1)
                a=h.assoc(1); child=a['child']
                self.assertNotIn(1,h.root.streams)
                self.assertEqual(child.h2_conn.streams[1].state_machine.state.name,'HALF_CLOSED_REMOTE')
                self.assertTrue(child.h2_conn.stream_buffers.get(1))
                self.assertFalse(any(isinstance(e,h2.events.StreamReset) and e.stream_id==1
                                     for e in h.peer_events['origin']))
                before=[h.inspect(1),h.inspect(3)]
                close=h.close_commands(1)
                if upstream_first: close.reverse()
                h.closed_callback(close[0].connection)
                after_first=h.inspect(1)
                h.closed_callback(close[1].connection)
                self.assertEqual(child._handle_event,child.done)
                self.assertFalse(child.streams)
                self.assertFalse(h.root.streams)
                count=len(h.out)
                h.closed_callback(close[0].connection)
                h.closed_callback(close[1].connection)
                h.origin.increment_flow_control_window(100, stream_id=1)
                h.from_origin()
                self.assertFalse(any(isinstance(x,commands.SendData) for x in h.out[count:]))
                REPORT.append(dict(case='orphan_close',upstream_first=upstream_first,
                                   before=before,after_first=after_first,after=h.inspect(1),
                                   sibling_after=h.inspect(3)))

    def test_reset_before_response_is_propagated(self):
        h=Harness(initial_window=0)
        h.headers(1); h.from_origin(); h.data(1,b'pending upload')
        h.reset(1)
        child=h.assoc(1)['child']
        self.assertEqual(child.h2_conn.streams[1].state_machine.state.name,'CLOSED')
        self.assertFalse(child.h2_conn.stream_buffers.get(1))
        self.assertTrue(any(isinstance(e,h2.events.StreamReset) and e.stream_id==1
                            for e in h.peer_events['origin']))
        REPORT.append(dict(case='reset_before_response',state=h.inspect(1)))

    def test_response_hook_paused_then_reset_is_queued(self):
        h=Harness(initial_window=0,hold={('response',1)})
        h.headers(1); h.from_origin(); h.data(1,b'pending upload')
        h.response(1)
        h.reset(1)
        paused=h.root.streams[1]
        self.assertTrue(paused._paused_event_queue)
        h.release(('response',1))
        child=h.assoc(1)['child']
        self.assertTrue(child.h2_conn.stream_buffers.get(1))
        REPORT.append(dict(case='response_hook_reset_order',state=h.inspect(1),
                           paused_queue=[type(x).__name__ for x in paused._paused_event_queue]))


    def test_buffered_upload_end_after_response_is_not_finished(self):
        h=Harness(initial_window=0)
        h.headers(1);h.from_origin();h.data(1,b'complete but buffered',end=True)
        h.response(1)
        child=h.assoc(1)['child']
        self.assertNotIn(1,h.root.streams)
        self.assertTrue(child.h2_conn.stream_buffers.get(1))
        self.assertTrue(child.h2_conn.stream_buffers[1][-1].end_stream)
        self.assertEqual(child.h2_conn.streams[1].state_machine.state.name,'HALF_CLOSED_REMOTE')
        before=h.inspect(1)
        h.origin.increment_flow_control_window(100, stream_id=1);h.from_origin()
        self.assertFalse(child.h2_conn.stream_buffers.get(1))
        self.assertEqual(child.h2_conn.streams[1].state_machine.state.name,'CLOSED')
        self.assertTrue(any(isinstance(x,h2.events.StreamEnded) and x.stream_id==1
                            for x in h.peer_events['origin']))
        REPORT.append(dict(case='response_done_upload_end_buffered',before=before,after=h.inspect(1)))

    def test_queue_progresses_through_dependency_not_adapter(self):
        h=Harness(max_streams=1)
        h.headers(1,end=True);h.from_origin();h.headers(3);h.data(3,b'later',end=True)
        self.assertEqual(h.assoc(3)['kind'],'queued')
        before=h.inspect(3)
        h.response(1)
        self.assertEqual(h.assoc(3)['kind'],'mapped')
        self.assertEqual(h.assoc(3)['ours'],3)
        self.assertFalse(h.assoc(3)['child'].stream_queue)
        self.assertTrue(any(isinstance(x,h2.events.RequestReceived) and x.stream_id==3
                            for x in h.peer_events['origin']))
        REPORT.append(dict(case='normal_queue_progress',before=before,after=h.inspect(3)))

    def test_no_buffer_orphan_still_needs_upstream_close(self):
        h=Harness()
        h.headers(1);h.from_origin();h.response(1);h.reset(1)
        child=h.assoc(1)['child']
        self.assertFalse(child.h2_conn.stream_buffers)
        self.assertEqual(child.h2_conn.streams[1].state_machine.state.name,'HALF_CLOSED_REMOTE')
        self.assertNotIn(1,h.root.streams)
        before=h.inspect(1)
        for cmd in h.close_commands(1):h.closed_callback(cmd.connection)
        self.assertEqual(child._handle_event,child.done)
        REPORT.append(dict(case='orphan_without_buffer',before=before,after=h.inspect(1)))

    def test_connecting_cancellation_requires_open_completion(self):
        for callback_before_completion in (False, True):
            with self.subTest(callback_before_completion=callback_before_completion):
                h=Harness(connected=False)
                h.headers(1);h.headers(3)
                a=h.assoc(1)
                h.close_commands(1)
                h.closed_callback(h.ctx.client)
                if callback_before_completion:
                    h.closed_callback(a['connection'])
                # Closing is a request. Establishment is still paused until completion.
                self.assertTrue(h.root.waiting_for_establishment)
                self.assertTrue(a['owner']._paused)
                a['connection'].state=connection.ConnectionState.CLOSED
                a['connection'].error='connection cancelled'
                h.run(events.OpenConnectionCompleted(h.opens[0],'connection cancelled'))
                self.assertFalse(h.root.waiting_for_establishment)
                self.assertFalse(h.root.command_sources)
                self.assertFalse(h.root.streams)
                self.assertIsNone(a['owner']._paused)
                self.assertIsNone(a['owner'].child_layer._paused)
                self.assertEqual(a['owner'].tunnel_state.name,'CLOSED')
                self.assertFalse(any(isinstance(x,commands.SendData) and
                                     x.connection is a['connection'] for x in h.out))
                REPORT.append(dict(case='connecting_cancel',
                                   synthetic_upstream_callback=callback_before_completion,
                                   waiting_count=len(h.root.waiting_for_establishment),
                                   root_stream_count=len(h.root.streams),
                                   pending_command_count=len(h.root.command_sources),
                                   owner_tunnel_state=a['owner'].tunnel_state.name,
                                   upstream_bytes_sent=0))

    def test_outer_handle_event_and_wakeup_survive_close(self):
        h=Harness(initial_window=0,probe=True)
        h.headers(1);h.from_origin();h.data(1,b'unfinished');h.response(1);h.reset(1)
        a=h.assoc(1)
        h.probe.close_request=(h.root,h.flows[1],1)
        begin=len(h.out)
        h.run(events.DataReceived(h.ctx.client,b''))
        emitted=[x for x in h.out[begin:] if isinstance(x,commands.CloseConnection)]
        self.assertEqual([x.connection for x in emitted],[h.ctx.client,a['connection']])
        self.assertIs(h.root.command_sources[h.probe.wakeup],h.probe)
        h.closed_callback(h.ctx.client)
        self.assertEqual(h.probe._handle_event,h.probe.done)
        self.assertNotEqual(a['child']._handle_event,a['child'].done)
        count=len(h.probe.callback_events)
        h.closed_callback(a['connection'])
        self.assertEqual(len(h.probe.callback_events),count) # upstream routes elsewhere
        h.run(events.Wakeup(h.probe.wakeup))
        self.assertEqual(h.probe.callback_events[-1],'Wakeup')
        self.assertEqual(a['child']._handle_event,a['child'].done)
        self.assertNotIn(h.probe.wakeup,h.root.command_sources)
        REPORT.append(dict(case='adapter_outer_handle_event_wakeup',
                           emitted_targets=['client','verified owned upstream'],
                           observer_saw_upstream_callback=False,
                           observer_saw_wakeup_after_client_done=True,
                           upstream_done_at_wakeup=True))


    def test_response_headers_then_reset_still_propagates(self):
        h=Harness(initial_window=0)
        h.headers(1);h.from_origin();h.data(1,b'pending upload');h.response(1,end=False)
        self.assertEqual(h.root.streams[1].server_state.__name__,'state_consume_response_body')
        h.reset(1)
        child=h.assoc(1)['child']
        self.assertEqual(child.h2_conn.streams[1].state_machine.state.name,'CLOSED')
        self.assertFalse(child.h2_conn.stream_buffers.get(1))
        self.assertTrue(any(isinstance(x,h2.events.StreamReset) and x.stream_id==1
                            for x in h.peer_events['origin']))
        REPORT.append(dict(case='response_headers_then_reset',state=h.inspect(1)))

    def test_upload_trailers_are_obligations_until_window_progress(self):
        h=Harness(initial_window=0)
        h.headers(1);h.from_origin();h.data(1,b'body before trailers')
        h.client.send_headers(1,[('x-proof-trailer','synthetic')],end_stream=True);h.from_client()
        h.response(1)
        child=h.assoc(1)['child']
        self.assertNotIn(1,h.root.streams)
        self.assertTrue(child.h2_conn.stream_buffers.get(1))
        self.assertEqual(child.h2_conn.stream_trailers[1],[(b'x-proof-trailer',b'synthetic')])
        before=h.inspect(1)
        h.origin.increment_flow_control_window(100,stream_id=1);h.from_origin()
        self.assertFalse(child.h2_conn.stream_buffers.get(1))
        self.assertNotIn(1,child.h2_conn.stream_trailers)
        self.assertEqual(child.h2_conn.streams[1].state_machine.state.name,'CLOSED')
        self.assertTrue(any(isinstance(x,h2.events.TrailersReceived) and x.stream_id==1
                            for x in h.peer_events['origin']))
        REPORT.append(dict(case='upstream_trailers',before=before,after=h.inspect(1)))


    def test_reconnecting_pending_match_precedes_stale_flow_pointer(self):
        h=Harness()
        h.headers(1,end=True);h.from_origin();h.response(1)
        old=h.assoc(1)
        h.closed_callback(old['connection'])
        h.headers(3)
        a=h.assoc(3)
        self.assertEqual(a['kind'],'connecting')
        self.assertIs(h.flows[3].server_conn,old['connection'])
        self.assertIsNot(a['connection'],old['connection'])
        self.assertEqual(old['child']._handle_event,old['child'].done)
        REPORT.append(dict(case='replacement_connection_stale_flow_pointer',state=h.inspect(3),
                           pending_exact_command_identity_takes_precedence=True))

    def test_connecting_flow_pointer_is_not_pending_connection(self):
        h=Harness(connected=False)
        h.headers(1);h.headers(3)
        a=h.assoc(1);b=h.assoc(3)
        self.assertEqual(a['kind'],'connecting')
        self.assertIs(a['connection'],b['connection'])
        self.assertIsNot(h.flows[1].server_conn,a['connection'])
        self.assertIsInstance(a['owner'],__import__('mitmproxy.proxy.layers.tls',fromlist=['ServerTLSLayer']).ServerTLSLayer)
        self.assertEqual(len(h.opens),1)
        REPORT.append(dict(case='connecting',states=[h.inspect(1),h.inspect(3)],
                           warning='flow.server_conn is the old context server until GetHttpConnectionCompleted'))


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Proof)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    Path(__file__).with_name('proof_results.json').write_text(json.dumps(REPORT,indent=2)+'\n')
    raise SystemExit(not result.wasSuccessful())
