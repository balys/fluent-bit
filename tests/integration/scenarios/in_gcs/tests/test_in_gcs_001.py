"""in_gcs against a local fake of the Pub/Sub pull API, GCS and the metadata server."""

import base64
import contextlib
import gzip
import http.server
import json
import os
import threading
import urllib.parse
from datetime import datetime, timezone

from utils.data_utils import read_file
from utils.test_service import FluentBitTestService


PROJECT = "test-project"
SUBSCRIPTION = "gcs-objects"
BUCKET = "logs"
SUBSCRIPTION_PATH = f"/v1/projects/{PROJECT}/subscriptions/{SUBSCRIPTION}"
EVENT_TIME = "2024-01-02T10:00:00.000000Z"


def _ms(text):
    return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp() * 1000)


def _notification(name, generation=1, event_type="OBJECT_FINALIZE"):
    attributes = {
        "bucketId": BUCKET,
        "objectId": name,
        "objectGeneration": str(generation),
        "eventType": event_type,
        "eventTime": EVENT_TIME,
        "payloadFormat": "JSON_API_V1",
    }
    data = json.dumps({"bucket": BUCKET, "name": name}).encode("utf-8")
    return {"data": base64.b64encode(data).decode("ascii"), "attributes": attributes}


class _FakeGoogle(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, objects, notifications, fail_downloads=None, fail_pulls=0):
        super().__init__(("127.0.0.1", 0), _FakeGoogleHandler)
        self.lock = threading.Lock()
        self.objects = objects
        self.queue = list(notifications)
        self.leased = {}
        self.deliveries = 0
        self.acked = []
        self.deadlines = []
        self.downloads = []
        self.authorization = []
        self.token_requests = []
        self.fail_downloads = dict(fail_downloads or {})
        self.fail_pulls = fail_pulls

    def pull(self, max_messages):
        with self.lock:
            batch = self.queue[:max_messages]
            del self.queue[:max_messages]
            received = []
            for message in batch:
                self.deliveries += 1
                ack_id = f"ack-{self.deliveries}"
                self.leased[ack_id] = message
                received.append({"ackId": ack_id, "message": message})
            return received

    def settled(self):
        with self.lock:
            return not self.queue and not self.leased


class _FakeGoogleHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _reply(self, status, body=b"", content_type="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_POST(self):
        server = self.server
        body = self._body()
        with server.lock:
            server.authorization.append(self.headers.get("Authorization"))

        if self.path == f"{SUBSCRIPTION_PATH}:pull":
            with server.lock:
                if server.fail_pulls > 0:
                    server.fail_pulls -= 1
                    self._reply(401, {"error": {"code": 401}})
                    return
            assert body.get("returnImmediately") is True
            received = server.pull(int(body["maxMessages"]))
            self._reply(200, {"receivedMessages": received} if received else {})
            return

        if self.path == f"{SUBSCRIPTION_PATH}:acknowledge":
            with server.lock:
                for ack_id in body["ackIds"]:
                    server.acked.append(server.leased.pop(ack_id)["attributes"]["objectId"])
            self._reply(200, {})
            return

        if self.path == f"{SUBSCRIPTION_PATH}:modifyAckDeadline":
            deadline = int(body["ackDeadlineSeconds"])
            with server.lock:
                for ack_id in body["ackIds"]:
                    message = server.leased[ack_id]
                    server.deadlines.append((message["attributes"]["objectId"], deadline))
                    if deadline == 0:
                        del server.leased[ack_id]
                        server.queue.append(message)
            self._reply(200, {})
            return

        self._reply(404, {"error": {"code": 404}})

    def do_GET(self):
        server = self.server
        url = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(url.query)

        if url.path == "/computeMetadata/v1/instance/service-accounts/default/token":
            if self.headers.get("Metadata-Flavor") != "Google":
                self._reply(403, {})
                return
            with server.lock:
                server.token_requests.append(self.path)
                token = f"token-{len(server.token_requests)}"
            self._reply(200, {"access_token": token, "expires_in": 3600,
                              "token_type": "Bearer"})
            return

        prefix = f"/storage/v1/b/{BUCKET}/o/"
        if not self.path.startswith(prefix):
            self._reply(404, {"error": {"code": 404}})
            return

        # the object name must arrive as one percent-encoded path segment
        encoded = url.path[len(prefix):]
        name = urllib.parse.unquote(encoded)
        with server.lock:
            server.authorization.append(self.headers.get("Authorization"))
            server.downloads.append((encoded, query.get("alt"), query.get("generation")))
            failures = server.fail_downloads.get(name, 0)
            if failures > 0:
                server.fail_downloads[name] = failures - 1

        if failures > 0:
            self._reply(503, {"error": {"code": 503}})
            return
        if name not in server.objects:
            self._reply(404, {"error": {"code": 404}})
            return
        self._reply(200, server.objects[name], "application/octet-stream")


@contextlib.contextmanager
def _fake_google(objects, notifications, **kwargs):
    server = _FakeGoogle(objects, notifications, **kwargs)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _write_config(tmp_path, port, input_options):
    parsers = tmp_path / "parsers.conf"
    parsers.write_text(
        "\n".join(
            [
                "[PARSER]",
                "    Name        iso_line",
                "    Format      regex",
                r"    Regex       ^(?<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z) (?<msg>.*)$",
                "    Time_Key    time",
                "    Time_Format %Y-%m-%dT%H:%M:%S.%LZ",
                "",
                "[PARSER]",
                "    Name        json_ts",
                "    Format      json",
                "    Time_Key    ts",
                "    Time_Format %Y-%m-%dT%H:%M:%S.%LZ",
                "",
                "[PARSER]",
                "    Name        key_time",
                "    Format      regex",
                r"    Regex       (?:^|/)dt=(?<time>\d{4}-\d{2}-\d{2}/hour=\d{2})/",
                "    Time_Key    time",
                "    Time_Format %Y-%m-%d/hour=%H",
                "",
            ]
        ),
        encoding="utf-8",
    )
    config = tmp_path / "in_gcs.conf"
    lines = [
        "[SERVICE]",
        "    Flush        0.2",
        "    Grace        2",
        "    Log_Level    debug",
        f"    Parsers_File {parsers}",
        "    HTTP_Server  On",
        "    HTTP_Port    ${FLUENT_BIT_HTTP_MONITORING_PORT}",
        "",
        "[INPUT]",
        "    Name             gcs",
        "    Tag              gcs",
        f"    subscription     {SUBSCRIPTION}",
        f"    project_id       {PROJECT}",
        f"    pubsub_endpoint  http://127.0.0.1:{port}",
        f"    storage_endpoint http://127.0.0.1:{port}",
        "    object_key       gcs_object",
        "    interval_sec     0",
        "    interval_nsec    200000000",
    ]
    lines += [f"    {option}" for option in input_options]
    lines += [
        "",
        "[OUTPUT]",
        "    Name             stdout",
        "    Match            gcs",
        "    Format           json_lines",
        "    json_date_key    date",
        "    json_date_format epoch_ms",
        "",
    ]
    config.write_text("\n".join(lines), encoding="utf-8")
    return config


def _records(log_file):
    records = []
    for line in read_file(log_file).splitlines():
        if line.startswith('{"date":'):
            records.append(json.loads(line))
    return records


def _run(tmp_path, server, input_options, expected_records):
    config = _write_config(tmp_path, server.server_address[1], input_options)
    service = FluentBitTestService(os.fspath(config))
    service.start()
    log_file = service.flb.log_file
    try:
        service.wait_for_condition(
            lambda: server.settled() and len(_records(log_file)) >= expected_records,
            timeout=30,
            interval=0.25,
            description=f"{expected_records} records and every notification settled",
        )
    finally:
        service.stop()
    return _records(log_file), read_file(log_file)


def test_in_gcs_reads_notified_objects(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    gz_name = "app/dt=2024-01-02/hour=04/host-1 ünï & more.log.gz"
    objects = {
        "app/dt=2024-01-02/hour=03/host-1_a.log": (
            b"2024-01-02T03:04:05.123Z first\n"
            b"2024-01-02T03:04:06.000Z second\n"
        ),
        # two gzip members, CRLF endings and a line that inherits the previous time
        gz_name: (
            gzip.compress(b"2024-01-02T04:00:01.000Z a\n")
            + gzip.compress(b"2024-01-02T04:00:02.000Z b\r\nno timestamp\r\n")
        ),
        # no timestamp at all: the time comes from the object name
        "app/dt=2024-01-02/hour=05/host-1_b.log": b"untimed one\n\nuntimed two",
        # no timestamp and no time in the name: the notification time
        "app/host-1_c.log": b"from event time\n",
        "app/empty.log": b"",
        "app/corrupt.log.gz": b"\x1f\x8b\x08\x00garbage",
    }
    notifications = [
        _notification(name) for name in objects
    ] + [
        _notification("app/missing.log"),
        _notification("app/dt=2024-01-02/hour=03/host-1_a.log", event_type="OBJECT_DELETE"),
    ]

    with _fake_google(objects, notifications) as server:
        records, log_text = _run(
            tmp_path, server,
            ["auth auto", "metadata_server http://127.0.0.1:%d" % server.server_address[1],
             "parser iso_line", "object_time_parser key_time", "max_messages 3"],
            expected_records=8,
        )

    got = sorted((r["date"], r["gcs_object"], r.get("msg", r.get("log"))) for r in records)
    assert got == sorted([
        (_ms("2024-01-02T03:04:05.123Z"), "app/dt=2024-01-02/hour=03/host-1_a.log", "first"),
        (_ms("2024-01-02T03:04:06.000Z"), "app/dt=2024-01-02/hour=03/host-1_a.log", "second"),
        (_ms("2024-01-02T04:00:01.000Z"), gz_name, "a"),
        (_ms("2024-01-02T04:00:02.000Z"), gz_name, "b"),
        (_ms("2024-01-02T04:00:02.000Z"), gz_name, "no timestamp"),
        (_ms("2024-01-02T05:00:00.000Z"), "app/dt=2024-01-02/hour=05/host-1_b.log",
         "untimed one"),
        (_ms("2024-01-02T05:00:00.000Z"), "app/dt=2024-01-02/hour=05/host-1_b.log",
         "untimed two"),
        (_ms("2024-01-02T10:00:00.000Z"), "app/host-1_c.log", "from event time"),
    ])

    # parsed lines carry the parsed map, unparsed ones the raw line under 'log'
    by_body = {r.get("msg", r.get("log")): set(r) for r in records}
    assert by_body["first"] == {"date", "msg", "gcs_object"}
    assert by_body["no timestamp"] == {"date", "log", "gcs_object"}

    assert sorted(server.acked) == sorted(n["attributes"]["objectId"] for n in notifications)
    assert server.deadlines == []

    downloaded = [d[0] for d in server.downloads]
    assert urllib.parse.quote(gz_name, safe="") in downloaded
    assert all(alt == ["media"] and generation == ["1"] for _, alt, generation in server.downloads)
    # the delete notification is acked without a download
    assert len(server.downloads) == len(notifications) - 1

    assert len(server.token_requests) == 1
    assert server.authorization and set(server.authorization) == {"Bearer token-1"}
    assert "is not valid gzip, skipping it" in log_text
    assert "no longer exists, skipping" in log_text


def test_in_gcs_redelivers_failed_downloads(tmp_path):
    name = "app/retry.ndjson"
    json_line = '{"ts": "2024-01-02T03:04:05.000Z", "msg": "kept raw"}'
    objects = {name: (json_line + "\nplain line\n").encode("utf-8")}

    with _fake_google(objects, [_notification(name, generation=7)],
                      fail_downloads={name: 2}) as server:
        records, log_text = _run(
            tmp_path, server,
            ["auth none", "parser json_ts", "raw_line on", "ack_deadline 30"],
            expected_records=2,
        )

    # raw_line keeps the line as is; the parser only supplies the time
    assert sorted((r["date"], r["log"]) for r in records) == sorted([
        (_ms("2024-01-02T03:04:05.000Z"), json_line),
        (_ms("2024-01-02T03:04:05.000Z"), "plain line"),
    ])
    # every delivery extends its lease; failed downloads hand the message back
    assert server.deadlines == [(name, 30), (name, 0), (name, 30), (name, 0), (name, 30)]
    assert server.acked == [name]
    assert server.deliveries == 3
    assert [d[2] for d in server.downloads] == [["7"]] * 3
    assert set(server.authorization) == {None}
    assert log_text.count("failed: status=503") == 2


def test_in_gcs_refreshes_token_after_401(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    name = "app/one.log"
    objects = {name: b"2024-01-02T03:04:05.000Z hello\n"}

    with _fake_google(objects, [_notification(name)], fail_pulls=1) as server:
        records, _ = _run(
            tmp_path, server,
            ["metadata_server http://127.0.0.1:%d" % server.server_address[1],
             "parser iso_line"],
            expected_records=1,
        )

    assert [r["msg"] for r in records] == ["hello"]
    assert len(server.token_requests) == 2
    assert server.authorization[0] == "Bearer token-1"
    assert set(server.authorization[1:]) == {"Bearer token-2"}
