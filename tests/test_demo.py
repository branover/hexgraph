"""`just demo` runs the offline loop and exits 0 (SPEC §10 acceptance)."""

import os


def test_demo_main_exits_zero(sandbox):
    from hexgraph import demo
    from hexgraph.db.session import reset_engine_for_tests

    saved_home = os.environ.get("HEXGRAPH_HOME")
    try:
        assert demo.main() == 0
    finally:
        if saved_home is not None:
            os.environ["HEXGRAPH_HOME"] = saved_home
        else:
            os.environ.pop("HEXGRAPH_HOME", None)
        reset_engine_for_tests()
