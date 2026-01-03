## Milestones

![](./img/joy.jpg)

### 🚧 bolt11

The first milestone is to create a valid bolt11 payment request that a fully fledged lightning node could pay if:

- there was a path
- the recipient node would actually know what to do with the incoming payment

No channels, no gossip, no routing information.

## Random Notes

* inspired by [`vimtutor`](https://vimschool.netlify.app/introduction/vimtutor/), [Saving Satoshi](https://savingsatoshi.com/) and [VIM adventures](https://vim-adventures.com/)
* alternative name was lnpilot

The idea was to make running a lightning node feel like flying a plane with only analog controls, because **fun + high interactivity lead to better results in education**. Since one of my motivations for this project is also to find security vulnerabilities in lightning—and for that, I first need to understand the protocol very well—I also wanted to connect it to aviation safety and the [second season of _The Rehearsal_](https://www.youtube.com/watch?v=6CaHP5P4wUc) in some way. Maybe I will consider this idea again later, but it sounds too ambitious and abstract for now.

* use [bubbletea](https://github.com/charmbracelet/bubbletea) as a beautiful TUI framework
* use [neutrino](https://github.com/lightninglabs/neutrino)
* use [mutinynet](https://faucet.mutinynet.com/)
* test my implementation against [lnprototest](https://github.com/rustyrussell/lnprototest) at some point
* build it like an app people _want_ to use, even if they are already familiar with the lightning network
  * [_The Secret Behind Weirdly Addictive Apps_](https://www.youtube.com/watch?v=Du2lkZ_cux8)

## Dependencies

To prevent that I'm just reusing the code of other people instead of writing my own lightning implementation, I am limiting myself to the following dependencies:

* [github.com/charmbracelet/bubbletea](https://github.com/charmbracelet/bubbletea)
* [github.com/charmbracelet/lipgloss](https://github.com/charmbracelet/lipgloss)
* [github.com/charmbracelet/bubbles](https://github.com/charmbracelet/bubbles)
* [github.com/decred/dcrd/dcrec/secp256k1/v4](https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4)
* [github.com/btcsuite/btcd/btcutil/bech32](https://pkg.go.dev/github.com/btcsuite/btcd/btcutil/bech32)

## References

* https://ellemouton.com/
* https://github.com/lightning/bolts
