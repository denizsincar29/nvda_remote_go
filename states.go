package nvda_remote_go

// ClientState represents the connection status of the client.
type ClientState int

const (
	// StateIdle means the client struct is created but no connection attempt made.
	StateIdle ClientState = iota
	// StateChecked means CheckServer completed, fingerprint info is available.
	StateChecked
	// StateTrusted means fingerprint check passed or was explicitly trusted.
	StateTrusted
	// StateConnecting means Connect() has been called, loops are starting.
	StateConnecting
	// StateConnected means loops are running and handshake sent.
	StateConnected
	// StateClosed means the connection is closed or was never fully established.
	StateClosed
)

// String returns a string representation of the ClientState.
func (s ClientState) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateChecked:
		return "checked"
	case StateTrusted:
		return "trusted"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// IsTrusted checks if the client is in a trusted state.
func (s ClientState) IsTrusted() bool {
	return s == StateTrusted || s == StateConnected
}

// IsConnected checks if the client is in a connected state.
func (s ClientState) IsConnected() bool {
	return s == StateConnected
}

// IsIdle checks if the client is in an idle state.
func (s ClientState) IsIdle() bool {
	return s == StateIdle
}

// IsChecked checks if the client has been checked.
func (s ClientState) IsChecked() bool {
	return s == StateChecked
}

// IsConnecting checks if the client is in a connecting state.
func (s ClientState) IsConnecting() bool {
	return s == StateConnecting
}

// VerificationStatus represents the outcome of the fingerprint check.
type VerificationStatus int

const (
	// VerificationNotChecked means CheckServer hasn't run or failed early.
	VerificationNotChecked VerificationStatus = iota
	// VerificationOK means the presented fingerprint matched the stored one.
	VerificationOK
	// VerificationUnknown means no fingerprint was stored for this host.
	VerificationUnknown
	// VerificationMismatch means a fingerprint was stored but didn't match.
	VerificationMismatch
	// VerificationError means an error occurred during verification (e.g., bad cert).
	VerificationError
)

// String returns a string representation of the VerificationStatus.
func (s VerificationStatus) String() string {
	switch s {
	case VerificationNotChecked:
		return "not checked"
	case VerificationOK:
		return "ok"
	case VerificationUnknown:
		return "unknown"
	case VerificationMismatch:
		return "mismatch"
	case VerificationError:
		return "error"
	default:
		return "unknown"
	}
}

// IsOK checks if the verification status is OK.
func (s VerificationStatus) IsOK() bool {
	return s == VerificationOK
}

// IsNotChecked checks if the verification status is not checked.
func (s VerificationStatus) IsNotChecked() bool {
	return s == VerificationNotChecked
}

// IsUnknown checks if the verification status is unknown.
func (s VerificationStatus) IsUnknown() bool {
	return s == VerificationUnknown
}

// IsMismatch checks if the verification status is a mismatch.
func (s VerificationStatus) IsMismatch() bool {
	return s == VerificationMismatch
}

// IsError checks if the verification status is an error.
func (s VerificationStatus) IsError() bool {
	return s == VerificationError
}

// StatusMessage returns a human-readable message for the verification status.
func (s VerificationStatus) StatusMessage() string {
	switch s {
	case VerificationNotChecked:
		return "Fingerprint not checked yet."
	case VerificationOK:
		return "Fingerprint matches the stored one."
	case VerificationUnknown:
		return "No fingerprint stored for this host."
	case VerificationMismatch:
		return "Fingerprint mismatch detected."
	case VerificationError:
		return "Error occurred during verification."
	default:
		return "Unknown verification status."
	}
}
