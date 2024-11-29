package proto

func fromhex(ch byte) int8 {
	if ch >= '0' && ch <= '9' {
		return int8(ch - '0')
	}
	if ch >= 'a' && ch <= 'f' {
		return int8(ch - 'a' + 10)
	}
	if ch >= 'A' && ch <= 'F' {
		return int8(ch - 'A' + 10)
	}
	return -1
}

// RFC1738Unescape is a port of Squid rfc1738_unescape function.
// It does unescaping in-place and returns slice pointing to boundaries of
// unescaped bytes.
func RFC1738Unescape(s []byte) []byte {
	var i, j int /* i is write, j is read */
	for ; j < len(s); i, j = i+1, j+1 {
		s[i] = s[j]
		if s[j] != '%' {
			/* normal case, nothing more to do */
		} else if j+1 < len(s) && s[j+1] == '%' { /* %% case */
			j++ /* Skip % */
		} else {
			if j+2 >= len(s) {
				continue
			}
			/* decode */
			var v1, v2 int8
			var x byte
			v1 = fromhex(s[j+1])
			if v1 < 0 {
				continue /* non-hex */
			}
			v2 = fromhex(s[j+2])
			if v2 < 0 {
				continue /* non-hex */
			}
			x = byte(v1)<<4 | byte(v2)
			if x > 0 && x <= 255 {
				s[i] = x
				j += 2
			}
		}
	}
	return s[:i]
}
