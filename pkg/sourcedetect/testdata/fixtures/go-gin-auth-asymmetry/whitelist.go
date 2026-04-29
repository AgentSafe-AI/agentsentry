package router

func IPWhiteList() HandlerFunc {
	return func(c *Context) {
		if len(whitelist) == 0 {
			c.Next()
			return
		}
	}
}
