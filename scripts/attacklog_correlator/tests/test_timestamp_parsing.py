from attacklog_correlator.ingestion import timestamps as ingestion_timestamps_module
from attacklog_correlator import models as models_module
import datetime as dt



def test_parse_apache_nginx_timestamp_with_offset():
    line = '127.0.0.1 - - [27/May/2026:13:01:57 +0200] "GET / HTTP/1.1" 200 612'

    parsed = ingestion_timestamps_module.parse_apache_nginx_timestamp(line, 2026)

    assert parsed is not None
    assert parsed.parser_name == "apache-nginx"
    assert parsed.naive is False
    assert parsed.timestamp_utc == dt.datetime(2026, 5, 27, 11, 1, 57, tzinfo=models_module.UTC)


def test_parse_json_line_timestamp_numeric_epoch_seconds():
    parsed = ingestion_timestamps_module.parse_json_line_timestamp('{"timestamp": 1710000000, "message": "hello"}', 2026)

    assert parsed is not None
    assert parsed.parser_name == "json:timestamp:epoch"
    assert parsed.timestamp_utc == dt.datetime.fromtimestamp(1710000000, tz=models_module.UTC)
