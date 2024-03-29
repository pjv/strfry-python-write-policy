# strfry Personal Relay Write Policy
This is python code for a [write policy plugin](https://github.com/hoytech/strfry/blob/master/docs/plugins.md) for the [strfry](https://github.com/hoytech/strfry) nostr relay that implements part of a personal relay solution. You may also be interested in my [set of configs](https://github.com/pjv/strfry_personal_docker) (using this write policy plugin) to make deploying a personal relay a 5-minute setup on a plain VPS. 

## Motivation
I think that in order for nostr to be what it can be, there needs to be a LOT of small relays all over everywhere as opposed to a short list of giant, "popular" relays that everyone uses which then must inevitably become centralized points of all manner of vulnerabilities that nostr is explicitly about avoiding.

Mike Dilger, author of the nostr client [gossip](https://github.com/mikedilger/gossip) as well as [NIP-65](https://github.com/nostr-protocol/nips/blob/master/65.md) wrote [The Gossip Model](https://mikedilger.com/gossip-model/) -- a description of how gossip manages relays in a way that can support this vision of having many smaller relays all over the place and still let people find the content they want to follow via nostr. In that document there is a section called **Personal Relays**. The _write policy_ in this repo is a first stab at implementing personal relays in that fashion.
