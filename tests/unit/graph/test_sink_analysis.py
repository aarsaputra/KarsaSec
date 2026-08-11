"""Unit tests for sink category classification (E11)."""

from karsasec.graph.dataflow.sinks import SinkCategory, sink_registry


def test_classify_command_execution_sinks() -> None:
    assert sink_registry.classify_sink("shell_exec", "shell_exec('ping ' . $ip)") == SinkCategory.COMMAND_EXECUTION
    assert sink_registry.classify_sink("exec", "exec($cmd)") == SinkCategory.COMMAND_EXECUTION
    assert sink_registry.classify_sink("system", "system('ls')") == SinkCategory.COMMAND_EXECUTION


def test_classify_sql_execution_sinks() -> None:
    assert sink_registry.classify_sink("query", "$db->query($sql)") == SinkCategory.SQL_EXECUTION
    assert sink_registry.classify_sink("mysqli_query", "mysqli_query($conn, $sql)") == SinkCategory.SQL_EXECUTION


def test_classify_file_inclusion_sinks() -> None:
    assert sink_registry.classify_sink("include", "include($file)") == SinkCategory.FILE_INCLUSION
    assert sink_registry.classify_sink("require_once", "require_once($file)") == SinkCategory.FILE_INCLUSION
