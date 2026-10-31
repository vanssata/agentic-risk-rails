package journal

func init() {
	MustRegister(
		Spec{Type: "risk_recorded", Module: "journal", Doc: "id, text, severity: a known risk left open"},
		Spec{Type: "risk_resolved", Module: "journal", Doc: "id: closes the risk_recorded with the same id"},
	)
}
