from pocsmith.budget import Budget


def test_no_reminder_below_75():
    b = Budget(wall_min=60, iterations=40, dollars=10.0, phases=8)
    b.tick(seconds=60, tokens_input=0, tokens_output=0, attempts=10, phases=2)
    assert b.reminder() is None


def test_reminder_at_75_iterations():
    b = Budget(wall_min=60, iterations=40, dollars=10.0, phases=8)
    b.tick(seconds=0, tokens_input=0, tokens_output=0, attempts=30, phases=0)
    r = b.reminder()
    assert r is not None and "iterations" in r.text and "75%" in r.text


def test_hard_stop_at_100():
    b = Budget(wall_min=60, iterations=40, dollars=10.0, phases=8)
    b.tick(seconds=0, tokens_input=0, tokens_output=0, attempts=40, phases=0)
    assert b.exhausted() == "iterations"


def test_dollar_tracks_input_output():
    b = Budget(wall_min=60, iterations=40, dollars=1.0, phases=8,
               input_per_mtok=15.0, output_per_mtok=75.0)
    b.tick(seconds=0, tokens_input=20_000, tokens_output=10_000, attempts=0, phases=0)
    spent = b.dollars_spent()
    assert abs(spent - 1.05) < 1e-9  # (20_000/1e6)*15.0 + (10_000/1e6)*75.0
