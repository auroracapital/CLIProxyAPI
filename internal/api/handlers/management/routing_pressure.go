package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetRoutingPressure returns an opaque, active-only least-pressure snapshot.
func (h *Handler) GetRoutingPressure(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	c.JSON(http.StatusOK, h.authManager.RoutingPressureSnapshot())
}
