package amcl

// CleanMemory set memory of slice to zero
func CleanMemory(arr []byte) {
	if len(arr) == 0 {
		return
	}
	arr[0] = 0
	for i := 1; i < len(arr); i *= 2 {
		copy(arr[i:], arr[:i])
	}
}
