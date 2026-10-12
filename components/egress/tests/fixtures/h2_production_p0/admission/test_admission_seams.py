"""P0-only interface evidence. No production addon, socket, or IPC claims."""
from collections import deque
from types import SimpleNamespace
import unittest

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import RequestReceived, StreamReset, ResponseReceived
from mitmproxy import connection, ctx
from unittest.mock import patch
from mitmproxy.net.http import status_codes
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers.http import (HTTPMode, HttpLayer, DropStream, RequestHeaders,
    ResponseProtocolError, HttpRequestHeadersHook)
from mitmproxy.proxy.layers.http._base import ReceiveHttp
from mitmproxy.proxy.layers.http._http2 import Http2Server


class SeamServer(Http2Server):
    """Test-only instance adaptation, preserving ordinary parser and hook path."""
    def __init__(self, context):
        super().__init__(context)
        self.pending = {}
        self.refused = set()
        self.raw_observed = []
        self.consumed = []
        self.exceptional = False
        self.missing_identity = False

    def consume_identity(self, request):
        item = self.pending.pop(id(request), None)
        if item is None or item[0] is not request:
            self.missing_identity = True
            raise ValueError('missing exact request identity')
        self.consumed.append(item[1])
        return item[1:]

    def handle_h2_event(self, event):
        if isinstance(event, RequestReceived):
            original = tuple(event.headers)
            self.raw_observed.append(original)
            produced = super().handle_h2_event(event)
            while True:
                try:
                    command = next(produced)
                except StopIteration as completed:
                    return completed.value
                if isinstance(command, ReceiveHttp) and isinstance(command.event, RequestHeaders):
                    request = command.event.request
                    self.pending[id(request)] = (request, event.stream_id, original)
                yield command
        if isinstance(event, StreamReset):
            for key, value in tuple(self.pending.items()):
                if value[1] == event.stream_id:
                    del self.pending[key]
        return (yield from super().handle_h2_event(event))

    def close_connection(self, msg):
        self.pending.clear()
        self.refused.clear()
        yield from super().close_connection(msg)

    def _handle_event(self, event):
        if self.missing_identity:
            self.exceptional = True
            yield from self.close_connection('P0 missing identity')
            if isinstance(event, ResponseProtocolError):
                yield DropStream(event.stream_id)
            return
        if isinstance(event, ResponseProtocolError) and event.stream_id in self.refused:
            sid = event.stream_id
            self.refused.remove(sid)
            if event.code != status_codes.NO_RESPONSE or self.h2_conn.stream_trailers.get(sid):
                self.exceptional = True
                # Suppress generated 400/413 instead of mislabelling a refusal.
                yield from self.close_connection('P0 unadmitted abnormal path')
                self.pending.clear()
                yield DropStream(sid)
                return
            if not self.is_closed(sid):
                self.h2_conn.reset_stream(sid, ErrorCodes.REFUSED_STREAM)
                data = self.h2_conn.data_to_send()
                if data:
                    yield commands.SendData(self.conn, data)
            self.streams.pop(sid, None)
            yield DropStream(sid)
            return
        yield from super()._handle_event(event)
        if isinstance(event, events.ConnectionClosed):
            self.pending.clear()
            self.refused.clear()


class Session:
    def __init__(self, *, body_limit=None, hold=False, deny=True):
        self.client = connection.Client(peername=('127.0.0.1', 1), sockname=('127.0.0.1', 2))
        self.client.alpn = b'h2'
        self.client.tls = True
        self.options = SimpleNamespace(proxy_debug=False, validate_inbound_headers=True, keep_host_header=False, body_size_limit=body_limit, stream_large_bodies=None, normalize_outbound_headers=True, connection_strategy="lazy", http2=True, http3=False, rawtcp=False, websocket=False, http2_ping_keepalive=0)
        self.context = Context(self.client, self.options)
        self.context.server.address = ('203.0.113.42', 443)
        self.context.server.tls = True
        self.http = HttpLayer(self.context, HTTPMode.transparent)
        self.layer = SeamServer(self.http.context.fork())
        self.http.connections[self.client] = self.layer
        self.peer = H2Connection(H2Configuration(client_side=True, validate_outbound_headers=False))
        self.commands = []
        self.peer_events = []
        self.hooks = []
        self.held = []
        self.identities = []
        self.hold = hold
        self.deny = deny
        self.peer.initiate_connection()
        self.dispatch(events.Start())
        self.flush()
        self.flush()

    def dispatch(self, event):
        queue = deque([event])
        while queue:
            event = queue.popleft()
            for cmd in self.http.handle_event(event):
                self.commands.append(cmd)
                if isinstance(cmd, commands.SendData) and cmd.connection is self.client:
                    self.peer_events.extend(self.peer.receive_data(cmd.data))
                elif isinstance(cmd, HttpRequestHeadersHook):
                    self.hooks.append(cmd)
                    if self.hold:
                        self.held.append(cmd)
                    else:
                        self.admission(cmd)
                        queue.append(events.HookCompleted(cmd))
                elif isinstance(cmd, commands.StartHook):
                    queue.append(events.HookCompleted(cmd))

    def admission(self, hook):
        try:
            sid, raw = self.layer.consume_identity(hook.flow.request)
        except ValueError:
            hook.flow.kill()
            return
        self.identities.append((sid, hook.flow.request, raw))
        if self.deny:
            self.layer.refused.add(sid)
            hook.flow.kill()

    def resume(self):
        for cmd in self.held[:]:
            self.held.remove(cmd)
            self.admission(cmd)
            self.dispatch(events.HookCompleted(cmd))

    def flush(self):
        data = self.peer.data_to_send()
        if data:
            self.dispatch(events.DataReceived(self.client, data))

    def headers(self, sid=1, *, scheme='https', authority='bound.example.com:443', extra=(), end=True):
        self.peer.send_headers(sid, [(':method','GET'),(':scheme',scheme),(':authority',authority),(':path','/v1/x'),*extra], end_stream=end)

    def assert_no_origin(self, test):
        test.assertFalse([c for c in self.commands if isinstance(c, commands.OpenConnection)])
        test.assertFalse([c for c in self.commands if isinstance(c, commands.SendData) and c.connection is not self.client])


class AdmissionSeams(unittest.TestCase):
    def test_configured_nextlayer_selector_preserves_installed_instance(self):
        from mitmproxy.addons.next_layer import NextLayer as Selector
        from mitmproxy.proxy.layer import NextLayer
        client = connection.Client(peername=('127.0.0.1', 1), sockname=('127.0.0.1', 2))
        client.alpn = b'h2'
        context = Context(client, SimpleNamespace(proxy_debug=False, validate_inbound_headers=True))
        from mitmproxy.proxy.layers.tls import ClientTLSLayer, ServerTLSLayer
        ServerTLSLayer(context)
        ClientTLSLayer(context)
        next_layer = NextLayer(context)
        selector = Selector()
        with patch.object(ctx, "options", SimpleNamespace(ignore_hosts=[], allow_hosts=[]), create=True):
            selector.next_layer(next_layer)
        owner = next_layer.layer
        self.assertIsInstance(owner, HttpLayer)
        adapted = SeamServer(owner.context.fork())
        owner.connections[client] = adapted
        selector.next_layer(next_layer)
        self.assertIs(next_layer.layer, owner)
        list(owner.handle_event(events.Start()))
        self.assertIs(owner.connections[client], adapted)


    def test_instance_slot_and_raw_identity_before_transparent_rewrite(self):
        s = Session()
        s.headers(scheme='http', authority='bound.example.com:81', extra=[('host','bound.example.com:81')])
        s.flush()
        self.assertIs(s.http.connections[s.client], s.layer)
        self.assertIsNot(Http2Server, SeamServer)
        sid, req, raw = s.identities[0]
        self.assertEqual(sid, 1)
        self.assertIs(req, s.hooks[0].flow.request)
        self.assertEqual((req.scheme, req.host, req.port), ('https','203.0.113.42',443))
        self.assertIn((b':scheme',b'http'), raw)
        self.assertIn((b':authority',b'bound.example.com:81'), raw)
        self.assertIn((b'host',b'bound.example.com:81'), raw)
        self.assertEqual(s.layer.consumed, [1])
        with self.assertRaises(ValueError):
            s.layer.consume_identity(req)
        s.assert_no_origin(self)

    def test_normal_kill_is_exact_refused_no_origin_and_three_table_cleanup(self):
        s = Session()
        for sid in range(1, 501, 2):
            s.headers(sid)
            s.flush()
            self.assertFalse(s.http.streams)
            self.assertFalse(s.http.command_sources)
            self.assertFalse(s.layer.streams)
            self.assertFalse(s.layer.pending)
            self.assertFalse(s.layer.refused)
            self.assertFalse(s.layer.h2_conn.stream_buffers)
            self.assertFalse(s.layer.h2_conn.stream_trailers)
        self.assertEqual([(e.stream_id,int(e.error_code)) for e in s.peer_events if isinstance(e,StreamReset)], [(sid,7) for sid in range(1,501,2)])
        self.assertEqual(len(s.hooks), 250)
        s.assert_no_origin(self)

    def test_400_check_invalid_cannot_be_relabelled_refused(self):
        s = Session()
        s.headers(scheme='ftp')
        s.flush()
        self.assertTrue(s.layer.exceptional)
        self.assertEqual(len(s.hooks), 1)
        self.assertFalse([e for e in s.peer_events if isinstance(e,(ResponseReceived,StreamReset))])
        self.assertTrue([c for c in s.commands if isinstance(c,commands.CloseConnection)])
        self.assertFalse(s.http.streams)
        self.assertFalse(s.layer.streams)
        self.assertFalse(s.layer.pending)
        s.assert_no_origin(self)

    def test_413_early_body_limit_cannot_be_relabelled_refused(self):
        s = Session(body_limit='1')
        s.headers(extra=[('content-length','100')], end=False)
        s.flush()
        self.assertTrue(s.layer.exceptional)
        self.assertEqual(len(s.hooks), 1)
        self.assertFalse([e for e in s.peer_events if isinstance(e,(ResponseReceived,StreamReset))])
        self.assertTrue([c for c in s.commands if isinstance(c,commands.CloseConnection)])
        self.assertFalse(s.http.streams)
        self.assertFalse(s.layer.streams)
        self.assertFalse(s.layer.pending)
        s.assert_no_origin(self)

    def test_paused_hook_keeps_identity_and_no_admission_until_consumed(self):
        s = Session(hold=True)
        s.headers()
        s.flush()
        self.assertEqual(len(s.layer.pending), 1)
        self.assertEqual(s.layer.consumed, [])
        self.assertEqual(len(s.hooks), 1)
        s.assert_no_origin(self)
        s.resume()
        self.assertEqual(s.layer.consumed, [1])
        self.assertFalse(s.layer.pending)
        self.assertFalse(s.http.streams)
        s.assert_no_origin(self)

    def test_same_batch_data_and_peer_rst_credit_and_cleanup(self):
        s = Session()
        window = s.layer.h2_conn._inbound_flow_control_window_manager
        before = window._bytes_processed
        s.headers(end=False)
        s.peer.send_data(1,b'hello',pad_length=7)
        s.peer.reset_stream(1)
        s.flush()
        self.assertEqual(window._bytes_processed-before, 13)
        self.assertFalse(s.http.streams)
        self.assertFalse(s.layer.streams)
        self.assertFalse(s.layer.pending)
        self.assertFalse(s.layer.refused)
        s.assert_no_origin(self)

    def test_reset_while_requestheaders_paused_clears_identity_and_late_hook_fails_closed(self):
        s = Session(hold=True)
        s.headers(end=False)
        s.flush()
        s.peer.reset_stream(1)
        s.flush()
        self.assertFalse(s.layer.pending)
        s.resume()
        self.assertEqual(s.layer.consumed,[])
        self.assertTrue(s.layer.exceptional)
        self.assertFalse(s.http.streams)
        self.assertFalse(s.layer.streams)
        self.assertFalse(s.layer.pending)
        self.assertFalse(s.layer.refused)
        s.assert_no_origin(self)

    def test_parse_error_stops_following_valid_stream_in_same_batch(self):
        s = Session(deny=False)
        s.headers(1, authority='bad.example:invalid')
        s.headers(3)
        s.flush()
        self.assertFalse(s.hooks)
        self.assertFalse(s.layer.pending)
        self.assertTrue([c for c in s.commands if isinstance(c, commands.CloseConnection)])
        s.assert_no_origin(self)

    def test_parse_error_before_hook_retains_no_identity(self):
        s = Session()
        s.headers(authority='bad.example:invalid')
        s.flush()
        self.assertFalse(s.hooks)
        self.assertFalse(s.layer.pending)
        self.assertTrue([c for c in s.commands if isinstance(c,commands.CloseConnection)])
        s.assert_no_origin(self)

class DisconnectSeam(unittest.TestCase):
    def test_disconnect_releases_pending_identity_even_with_hook_paused(self):
        s = Session(hold=True)
        s.headers(end=False)
        s.flush()
        self.assertEqual(len(s.layer.pending), 1)
        s.dispatch(events.ConnectionClosed(s.client))
        self.assertFalse(s.layer.pending)
        self.assertFalse(s.layer.refused)
        # Native close changes _handle_event to done; the outer owner must
        # handle late callback cleanup rather than rely on that old method.
        self.assertEqual(s.layer._handle_event, s.layer.done)
        s.resume()
        self.assertFalse(s.layer.pending)
        s.assert_no_origin(self)


if __name__ == '__main__':
    unittest.main(verbosity=2)
