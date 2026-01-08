## Milestones

### ✅ bolt11

The first milestone is to create a valid bolt11 payment request that a fully
fledged lightning node could pay if:

- there was a path
- the recipient node would actually know what to do with the incoming payment

No channels, no gossip, no routing information.

### 🚧 bolt11 tool

The second milestone is about a tool in the TUI that explains bolt11 payment
requests. I want it to be very detailed; ideally, it should cover everything
I've learned myself, including, but not necessarily limited to:

* bech32 encoding
  - hrp
    * network prefix
    * amount
  - data part
    * timestamp
    * tagged fields
    * signature
  - how to convert bits from 8-bit to 5-bit groups
  - how 5-bit groups are mapped to characters
  - bip173 vs bolt11 w/o limit

* tagged fields
  - elements
    * `type` (5 bits)
    * `data_length` (10 bits, big-endian)
    * `data` (`data_length` x 5)
  - big-endian vs little-endian
  - which types exist? what is their purpose?
  - which types are required/optional/repeatable?
* signature
  - secp256k1
  - high-S vs low-S

Additionally, expectations for the following tools should be set. It's the first
time I'm providing a TUI to learn about lightning.

## Random Notes

* inspired by
  [vimtutor](https://vimschool.netlify.app/introduction/vimtutor/), [Saving
  Satoshi](https://savingsatoshi.com/), [learn me a
  bitcoin](https://learnmeabitcoin.com/)
* alternative name was lnpilot

The idea was to make running a lightning node feel like flying a plane with only
analog controls, because **fun + high interactivity lead to better results in
education**. Since one of my motivations for this project is also to find
security vulnerabilities in lightning—and for that, I first need to understand
the protocol very well—I also wanted to connect it to aviation safety and the
[second season of _The Rehearsal_](https://www.youtube.com/watch?v=6CaHP5P4wUc)
in some way. Maybe I will consider this idea again later, but it sounds too
ambitious and abstract for now.

* use [bubbletea](https://github.com/charmbracelet/bubbletea) as a beautiful TUI
  framework
* use [neutrino](https://github.com/lightninglabs/neutrino)
* use [mutinynet](https://faucet.mutinynet.com/)
* test my implementation against
  [lnprototest](https://github.com/rustyrussell/lnprototest) at some point
* build it like an app people _want_ to use, even if they are already familiar
  with the lightning network
  * [_The Secret Behind Weirdly Addictive
    Apps_](https://www.youtube.com/watch?v=Du2lkZ_cux8)

Update Jan 8, 2026:

I don't want to do a bunch of stuff around the thing I actually want to do:
implement lightning.

I care about educating people, but I don't want to think about chapters, how to
gamify it, etc. It wouldn't be something I'm building for myself, because while
building it, I wouldn't need it myself anymore.

Instead, I want to have a TUI that exposes all the things about lightning. I
want to have tools, not chapters.

I want to build lnpilot, not lntutor.

## Dependencies

To prevent that I'm just reusing the code of other people instead of writing my
own lightning implementation, I am limiting myself to the following
dependencies:

* [github.com/charmbracelet/bubbletea](https://github.com/charmbracelet/bubbletea)
* [github.com/charmbracelet/lipgloss](https://github.com/charmbracelet/lipgloss)
* [github.com/charmbracelet/bubbles](https://github.com/charmbracelet/bubbles)
* [github.com/decred/dcrd/dcrec/secp256k1/v4](https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4)
* [github.com/btcsuite/btcd/btcutil/bech32](https://pkg.go.dev/github.com/btcsuite/btcd/btcutil/bech32)

## References

* https://ellemouton.com/
* https://github.com/lightning/bolts
