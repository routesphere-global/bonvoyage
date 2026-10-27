package adminapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/adminservice"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/rollout"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

func writePrometheus(response http.ResponseWriter, telemetry adminservice.OperationalTelemetry) {
	response.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write([]byte(renderPrometheus(telemetry)))
}

func renderPrometheus(telemetry adminservice.OperationalTelemetry) string {
	var output strings.Builder
	writeGaugeHeader(&output, "bonvoyage_control_plane_ready", "Whether durable and runtime rollout authority agree.")
	writeGauge(&output, "bonvoyage_control_plane_ready", nil, boolMetric(telemetry.Ready))
	writeGaugeHeader(&output, "bonvoyage_control_plane_process_start_time_seconds", "Control-plane process start time as Unix seconds.")
	writeGauge(&output, "bonvoyage_control_plane_process_start_time_seconds", nil, telemetry.ProcessStartedAt.Unix())
	writeGaugeHeader(&output, "bonvoyage_control_plane_runtime_authority_match", "Whether repository selection and live coordinator sequence agree.")
	writeGauge(&output, "bonvoyage_control_plane_runtime_authority_match", nil, boolMetric(telemetry.RuntimeAuthorityMatch))
	writeGaugeHeader(&output, "bonvoyage_control_plane_selected_rollout_sequence", "Persisted selected rollout sequence.")
	writeGauge(&output, "bonvoyage_control_plane_selected_rollout_sequence", nil, telemetry.SelectedSequence)

	writeGaugeHeader(&output, "bonvoyage_control_plane_rollout_phase", "One-hot selected rollout phase.")
	for _, phase := range []rollout.Phase{
		rollout.PhasePending, rollout.PhasePreparing, rollout.PhaseActivating,
		rollout.PhaseObserving, rollout.PhaseActive, rollout.PhaseCancelled,
		rollout.PhaseRequiresRollback,
	} {
		writeGauge(&output, "bonvoyage_control_plane_rollout_phase", map[string]string{"phase": string(phase)}, boolMetric(phase == telemetry.RolloutPhase))
	}
	writeGaugeHeader(&output, "bonvoyage_control_plane_rollout_kind", "One-hot selected rollout intent kind.")
	for _, kind := range []storage.RolloutKind{storage.RolloutKindApply, storage.RolloutKindRollback} {
		writeGauge(&output, "bonvoyage_control_plane_rollout_kind", map[string]string{"kind": string(kind)}, boolMetric(kind == telemetry.RolloutKind))
	}
	writeGaugeHeader(&output, "bonvoyage_control_plane_rollout_policy", "One-hot persisted rollout policy strategy.")
	for _, strategy := range []string{"DISABLED", "IMMEDIATE", "CANARY"} {
		writeGauge(&output, "bonvoyage_control_plane_rollout_policy", map[string]string{"strategy": strategy}, boolMetric(strategy == telemetry.PolicyStrategy))
	}
	writeGaugeHeader(&output, "bonvoyage_control_plane_rollout_policy_enabled", "Whether selected rollout policy reconciliation is enabled.")
	writeGauge(&output, "bonvoyage_control_plane_rollout_policy_enabled", nil, boolMetric(telemetry.PolicyEnabled))
	writeGaugeHeader(&output, "bonvoyage_control_plane_automatic_rollback_enabled", "Whether selected rollout permits automatic exact rollback.")
	writeGauge(&output, "bonvoyage_control_plane_automatic_rollback_enabled", nil, boolMetric(telemetry.AutomaticRollback))

	writeGaugeHeader(&output, "bonvoyage_control_plane_target_nodes", "Target nodes in the selected immutable rollout.")
	writeGauge(&output, "bonvoyage_control_plane_target_nodes", nil, telemetry.TargetNodes)
	writeGaugeHeader(&output, "bonvoyage_control_plane_connected_nodes", "Target nodes with a current authenticated discovery owner.")
	writeGauge(&output, "bonvoyage_control_plane_connected_nodes", nil, telemetry.ConnectedNodes)
	writeGaugeHeader(&output, "bonvoyage_control_plane_reconciled_nodes", "Target nodes reconciled with selected authority.")
	writeGauge(&output, "bonvoyage_control_plane_reconciled_nodes", nil, telemetry.ReconciledNodes)
	writeGaugeHeader(&output, "bonvoyage_control_plane_unreconciled_nodes", "Target nodes not reconciled with selected authority.")
	writeGauge(&output, "bonvoyage_control_plane_unreconciled_nodes", nil, telemetry.UnreconciledNodes)
	writeGaugeHeader(&output, "bonvoyage_control_plane_pending_commands", "Commands queued across current authenticated target owners.")
	writeGauge(&output, "bonvoyage_control_plane_pending_commands", nil, telemetry.PendingCommands)
	writeGaugeHeader(&output, "bonvoyage_control_plane_node_phase", "Target-node count by fixed rollout phase.")
	for _, count := range telemetry.NodePhases {
		writeGauge(&output, "bonvoyage_control_plane_node_phase", map[string]string{"phase": count.Name}, count.Count)
	}

	writeGaugeHeader(&output, "bonvoyage_control_plane_journal_events", "Accepted events in the selected durable journal.")
	writeGauge(&output, "bonvoyage_control_plane_journal_events", nil, telemetry.JournalEvents)
	writeGaugeHeader(&output, "bonvoyage_control_plane_journal_event_kind", "Accepted selected-journal events by fixed kind.")
	for _, count := range telemetry.JournalKinds {
		writeGauge(&output, "bonvoyage_control_plane_journal_event_kind", map[string]string{"kind": count.Name}, count.Count)
	}
	writeGaugeHeader(&output, "bonvoyage_control_plane_journal_transition_errors", "Accepted journal transitions with a deterministic error outcome.")
	writeGauge(&output, "bonvoyage_control_plane_journal_transition_errors", nil, telemetry.JournalTransitionErrors)
	writeGaugeHeader(&output, "bonvoyage_control_plane_rollout_reports", "Durable node reports by fixed operation and result.")
	for _, count := range telemetry.Reports {
		writeGauge(&output, "bonvoyage_control_plane_rollout_reports", map[string]string{
			"operation": string(count.Operation), "result": string(count.Result),
		}, count.Count)
	}
	writeGaugeHeader(&output, "bonvoyage_control_plane_policy_decisions", "Durable state-changing policy decisions by fixed outcome.")
	for _, count := range telemetry.PolicyDecisions {
		writeGauge(&output, "bonvoyage_control_plane_policy_decisions", map[string]string{"decision": count.Name}, count.Count)
	}
	writeGaugeHeader(&output, "bonvoyage_control_plane_last_journal_event_timestamp_seconds", "Creation time of the latest selected-journal event as Unix seconds.")
	lastEvent := int64(0)
	if !telemetry.LastJournalEventAt.IsZero() {
		lastEvent = telemetry.LastJournalEventAt.Unix()
	}
	writeGauge(&output, "bonvoyage_control_plane_last_journal_event_timestamp_seconds", nil, lastEvent)
	writeGaugeHeader(&output, "bonvoyage_control_plane_recovery_required", "Whether authority mismatch or rollout state requires operator recovery.")
	writeGauge(&output, "bonvoyage_control_plane_recovery_required", nil, boolMetric(telemetry.RecoveryRequired))
	return output.String()
}

func writeGaugeHeader(output *strings.Builder, name, help string) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
}

func writeGauge(output *strings.Builder, name string, labels map[string]string, value any) {
	output.WriteString(name)
	if len(labels) != 0 {
		output.WriteByte('{')
		first := true
		for _, label := range []string{"decision", "kind", "operation", "phase", "result", "strategy"} {
			labelValue, found := labels[label]
			if !found {
				continue
			}
			if !first {
				output.WriteByte(',')
			}
			first = false
			fmt.Fprintf(output, "%s=%q", label, labelValue)
		}
		output.WriteByte('}')
	}
	fmt.Fprintf(output, " %v\n", value)
}

func boolMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}
