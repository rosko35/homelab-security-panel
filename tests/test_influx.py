import asyncio
import json

import httpx
import pytest

from homesec.config import InfluxConfig
from homesec.influx import InfluxWriter, NullWriter, Point, build_writer


def test_line_protocol_escaping_and_types():
    p = Point(
        "homesec scan,x",
        {"host": "nas lab", "kind": "a=b,c", "empty": ""},
        {"ports": 3, "ratio": 0.5, "ok": True, "msg": 'say "hi"\\now\nnext', "skip": None},
        1700000000,
    )
    assert p.to_line() == (
        r"homesec\ scan\,x,host=nas\ lab,kind=a\=b\,c "
        r'ports=3i,ratio=0.5,ok=true,msg="say \"hi\"\\now next" 1700000000'
    )


def test_point_without_fields_is_rejected():
    with pytest.raises(ValueError):
        Point("m", {"a": "b"}, {"x": None}).to_line()


class FakeInflux:
    def __init__(self, bucket_exists=False):
        self.bucket_exists = bucket_exists
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/api/v2/buckets" and request.method == "GET":
            buckets = [{"name": "homelab"}] if self.bucket_exists else []
            return httpx.Response(200, json={"buckets": buckets})
        if path == "/api/v2/orgs":
            return httpx.Response(200, json={"orgs": [{"id": "org123", "name": "iot"}]})
        if path == "/api/v2/buckets" and request.method == "POST":
            self.bucket_exists = True
            return httpx.Response(201, json={"id": "b1"})
        if path == "/api/v2/write":
            return httpx.Response(204)
        return httpx.Response(404)


def test_writer_creates_bucket_once_and_writes():
    fake = FakeInflux()
    writer = InfluxWriter(
        "http://influx.test:8086/",
        "iot",
        "homelab",
        "tok",
        retention_s=86400,
        transport=httpx.MockTransport(fake.handler),
    )

    async def go():
        try:
            assert await writer.write([Point("m", {"t": "1"}, {"v": 1}, 10)])
            assert await writer.write([Point("m", {}, {"v": 2})])
        finally:
            await writer.aclose()

    asyncio.run(go())
    methods = [(r.method, r.url.path) for r in fake.requests]
    assert methods == [
        ("GET", "/api/v2/buckets"),
        ("GET", "/api/v2/orgs"),
        ("POST", "/api/v2/buckets"),
        ("POST", "/api/v2/write"),
        ("POST", "/api/v2/write"),
    ]
    create = json.loads(fake.requests[2].content)
    assert create == {
        "name": "homelab",
        "orgID": "org123",
        "retentionRules": [{"type": "expire", "everySeconds": 86400}],
    }
    write = fake.requests[3]
    assert write.headers["Authorization"] == "Token tok"
    assert write.url.params["bucket"] == "homelab"
    assert write.url.params["precision"] == "s"
    assert write.content == b"m,t=1 v=1i 10"
    # points without a timestamp get "now"
    assert fake.requests[4].content.decode().startswith("m v=2i ")


def test_write_failure_is_reported_not_raised():
    def down(request):
        raise httpx.ConnectError("refused")

    writer = InfluxWriter(
        "http://x", "iot", "b", "t", create_bucket=False, transport=httpx.MockTransport(down)
    )

    async def go():
        try:
            return await writer.write([Point("m", {}, {"v": 1})])
        finally:
            await writer.aclose()

    assert asyncio.run(go()) is False


def test_build_writer_without_url_is_null():
    assert isinstance(build_writer(InfluxConfig()), NullWriter)
    w = build_writer(InfluxConfig(url="http://localhost:8086", token="x"))
    assert isinstance(w, InfluxWriter)
    asyncio.run(w.aclose())
