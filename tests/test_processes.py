from examples.three_node import run_demo


def test_three_independent_processes_persist_cache_and_relay_revocation(tmp_path):
    result = run_demo(tmp_path)
    assert result["status"] == "passed"
    assert len(set(result["initial_server_pids"])) == 3
    assert result["restarted_bob_pid"] not in result["initial_server_pids"]
    assert len(set(result["node_directories"])) == 3
