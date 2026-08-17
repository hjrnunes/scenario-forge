from pathlib import Path
from scenario_forge.stpa.models.control_structure import (
    ControlAction, ControlledProcess, ElementRef, FeedbackChannel,
    ProcessModelPart, ReferenceType, Responsibility,
)
from scenario_forge.stpa.system_model.control_structure import (
    ControlElementSet, ResponsibilitySet, _assemble_with_fallback,
)

# Call 2a output: responsibilities with RCs + PM parts only (no CAs/FBs)
rs = ResponsibilitySet(responsibilities=[
    Responsibility(
        resp_id="RESP-1", description="Controller 1",
        process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
        control_actions=[], feedback_channels=[],
    )
])

# Call 2b output: CAs/FBs/CPs. CA-1-1 has a VALID target; FB-1-1 has an INVALID source
# (RESP-99 does not exist), which is what forces the fallback path.
ces = ControlElementSet(
    control_actions=[ControlAction(
        ca_id="CA-1-1", description="Act",
        target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"))],
    feedback_channels=[FeedbackChannel(
        fb_id="FB-1-1", description="FB", updates="PM-1-1",
        source=ElementRef(type=ReferenceType.responsibility, id="RESP-99"))],
    controlled_processes=[ControlledProcess(cp_id="CP-1", description="Process")],
)

cs, warnings = _assemble_with_fallback(rs, ces, Path("tmp"), "probe-model")
r0 = cs.responsibilities[0]
print("fallback taken:", bool(warnings))
print("controlled_processes preserved:", [c.cp_id for c in cs.controlled_processes])
print("control_actions on RESP-1   :", [c.ca_id for c in r0.control_actions])
print("feedback_channels on RESP-1 :", [f.fb_id for f in r0.feedback_channels])
