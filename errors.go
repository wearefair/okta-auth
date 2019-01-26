package okta

// Used to indicate that the current authentication flow cannot proceed.
// When a terminal error is returned, the program should print the error and
// exit with a non zero status code.
type TerminalError string

func (e TerminalError) String() string { return string(e) }
func (e TerminalError) Error() string  { return string(e) }
