package stogas

import (
	"context"

	"github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
	"github.com/valyala/fasthttp"
)

// chutesStandardCallKey marks a Chutes call whose deployment is on the standard route.
type chutesStandardCallKey struct{}

// SetChutesCall passes a Chutes provider call into the transport of the route that its deployment
// is on. An end-to-end encrypted route takes the chute and GPU count that the deployment names, and
// chutese2ee sends it. A standard route sends the call to Chutes' own API over ordinary TLS, where
// nothing is encrypted end to end, so its reply carries no encryption proof.
func SetChutesCall(ctx *schemas.BifrostContext, resolution *catalog.ResolvedRequest, attempts int, retryAllowed func() bool) {
	if resolution.Deployment.DataHandling.EndToEndEncrypted {
		upstream := resolution.Deployment.Upstream
		target := chutese2ee.ModelTarget{ChuteID: upstream.ChuteID}
		if upstream.GPUCount != nil {
			target.GPUCount = *upstream.GPUCount
		}
		chutese2ee.SetInvocation(ctx, target, attempts, retryAllowed)
		return
	}
	ctx.SetValue(chutesStandardCallKey{}, true)
}

// chutesTransport is the custom transport of the Chutes provider. A call without a route decision
// takes the encrypted path, which refuses a call that has no invocation before it sends anything.
type chutesTransport struct {
	encrypted interface {
		DoRequestWithContext(context.Context, *fasthttp.Request, *fasthttp.Response) error
	}
	standard *fasthttp.Client
}

// RoundTrip serves fasthttp's interface. Core calls DoRequestWithContext, which carries the decision.
func (t *chutesTransport) RoundTrip(_ *fasthttp.HostClient, request *fasthttp.Request, response *fasthttp.Response) (bool, error) {
	return false, t.DoRequestWithContext(context.Background(), request, response)
}

// IsStandardCall reports a Chutes call that goes to Chutes' own API rather than through chutese2ee.
func IsStandardCall(ctx context.Context) bool {
	standard, _ := ctx.Value(chutesStandardCallKey{}).(bool)
	return standard
}

func (t *chutesTransport) DoRequestWithContext(ctx context.Context, request *fasthttp.Request, response *fasthttp.Response) error {
	if IsStandardCall(ctx) {
		return utils.DoRequestWithContext(ctx, t.standard, request, response)
	}
	return t.encrypted.DoRequestWithContext(ctx, request, response)
}
