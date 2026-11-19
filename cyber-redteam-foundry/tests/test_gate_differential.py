from cyberredteam.contracts import TechniqueResult
from cyberredteam.gate import GatePolicy, GateStatus, TechniqueOverride, TechniqueStatus, compare


def tr(name, trials, confirmed):
    return TechniqueResult.from_counts(name, trials, confirmed)


def status_of(result, name):
    return next(d.status for d in result.diffs if d.technique == name)


def test_pass_identical():
    r = compare([tr("a", 20, 2)], [tr("a", 20, 2)])
    assert r.status is GateStatus.PASS and r.exit_code == 0


def test_regression_flagged():
    r = compare([tr("a", 20, 0)], [tr("a", 20, 12)])
    assert r.status is GateStatus.REGRESSION and r.exit_code == 1
    assert status_of(r, "a") is TechniqueStatus.REGRESSION


def test_improvement_not_flagged():
    r = compare([tr("a", 20, 12)], [tr("a", 20, 0)])
    assert r.status is GateStatus.PASS
    assert status_of(r, "a") is TechniqueStatus.IMPROVED


def test_overlapping_cis_pass():
    r = compare([tr("a", 20, 4)], [tr("a", 20, 8)])
    assert r.status is GateStatus.PASS
    assert status_of(r, "a") is TechniqueStatus.UNCHANGED


def test_too_few_trials_inconclusive():
    r = compare([tr("a", 20, 0)], [tr("a", 3, 3)])
    assert r.status is GateStatus.INCONCLUSIVE and r.exit_code == 2


def test_regression_beats_inconclusive():
    r = compare([tr("a", 20, 0), tr("b", 20, 0)], [tr("a", 20, 12), tr("b", 2, 0)])
    assert r.status is GateStatus.REGRESSION


def test_new_technique_warn_and_fail():
    warn = compare([tr("a", 20, 1)], [tr("a", 20, 1), tr("n", 20, 9)])
    assert warn.status is GateStatus.PASS and warn.warnings
    assert status_of(warn, "n") is TechniqueStatus.NEW
    fail = compare([tr("a", 20, 1)], [tr("a", 20, 1), tr("n", 20, 9)],
                   GatePolicy(new_technique="fail"))
    assert fail.status is GateStatus.REGRESSION


def test_missing_technique_inconclusive_or_ignored():
    r = compare([tr("a", 20, 1), tr("m", 20, 1)], [tr("a", 20, 1)])
    assert r.status is GateStatus.INCONCLUSIVE
    assert status_of(r, "m") is TechniqueStatus.MISSING
    ok = compare([tr("a", 20, 1), tr("m", 20, 1)], [tr("a", 20, 1)],
                 GatePolicy(missing_technique="ignore"))
    assert ok.status is GateStatus.PASS


def test_overrides_min_trials_skip_and_delta():
    base, cand = [tr("a", 4, 0)], [tr("a", 4, 4)]
    assert compare(base, cand).status is GateStatus.INCONCLUSIVE
    p = GatePolicy(overrides={"a": TechniqueOverride(min_trials=4)})
    assert compare(base, cand, p).status is GateStatus.REGRESSION
    p = GatePolicy(overrides={"a": TechniqueOverride(skip=True)})
    assert compare(base, cand, p).status is GateStatus.INCONCLUSIVE  # nothing compared
    p = GatePolicy(min_rate_increase=0.9)
    assert compare([tr("a", 20, 0)], [tr("a", 20, 12)], p).status is GateStatus.PASS


def test_empty_inputs_not_a_pass():
    assert compare([], []).status is GateStatus.INCONCLUSIVE
