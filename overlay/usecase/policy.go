// Modified for XConnect-One: standalone module imports.
package usecase

import (
	"errors"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/policy"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
)

func AcceptPolicyArtifact(store *state.Store, raw []byte, reference policy.VerifiedReference, now time.Time) (policy.Accepted, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	floor := policy.Floor{}
	current, err := store.LoadPolicyState()
	if err == nil {
		floor = policy.Floor{NetworkID: current.NetworkID, Generation: current.Generation, Digest: current.Digest}
	} else if !errors.Is(err, state.ErrNotFound) {
		return policy.Accepted{}, err
	}
	accepted, err := policy.Consume(raw, reference, floor, now)
	if err != nil {
		return policy.Accepted{}, err
	}
	if err := store.SavePolicyState(state.PolicyState{
		NetworkID: accepted.Artifact.NetworkID, Generation: accepted.Generation,
		Digest: accepted.Digest, Revision: accepted.Artifact.Revision,
		ExpiresAt: accepted.ExpiresAt, AcceptedAt: now.UTC(),
	}); err != nil {
		return policy.Accepted{}, err
	}
	return accepted, nil
}
