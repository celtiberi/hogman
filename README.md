<p align="center">
  <a href="https://hogman.network"><img src="site/public/logo.webp" alt="HÖGMAN" width="560"></a>
</p>

<p align="center"><strong>A PRIVATE INTERNET · BY INVITATION · NO MERCY</strong></p>

<p align="center">
  <a href="LICENSE"><img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-ff6a1a"></a>
  <img alt="Status: experimental" src="https://img.shields.io/badge/status-experimental-d1281c">
  <a href="https://hogman.network"><img alt="hogman.network" src="https://img.shields.io/badge/web-hogman.network-ffc233"></a>
</p>

<p align="center">
  <img src="site/public/hero.webp" alt="The Top Hog Farmer, in studded black leather, plants a boot on the fence. Clean pigs in sunglasses stand calm inside the pen; a filthy horde claws at the rails outside. The sign reads: Clean Pigs Only!" width="100%">
</p>

# Your pen. Your rules. Clean pigs only.

**Get a pen:** [get.hogman.network](https://get.hogman.network). Free while we test it; sign-ups
are by invitation for now.

**Or run your own server:**

```bash
curl -fsSL https://hogman.network/install.sh | sudo bash     # on a fresh Ubuntu 24.04 server
```

Invited to someone's pen? You don't install anything up front: open the invite link and
copy the one command its page gives you.


Hogman gives you your own **private internet** for the people you choose. Get a pen on our
server in about a minute, or raise one on your own. You hold the gate. Your swine get real
names, real websites and real padlocks. The filthy horde stays outside the fence, howling.

## In plain words

**Your own little internet, with a guest list.** You make a private network and invite the
people you want. Inside it you can have websites, message boards, photo pages, anything you'd
normally use in a browser, and they work just like the sites you already visit. The
difference: only the people you let in can reach them.

**From the outside, there is nothing there.** Your sites don't have public addresses, so
strangers, scrapers and attackers can't find them, can't load them and can't try to break in.
There's no login page for them to guess at.

**You stay in charge.** You hand out invitations, everyone gets a proper name, and if someone
misbehaves you remove them, every device at once, in about two seconds.

**What people use it for.** You bring the apps (a photo gallery, a forum, a wiki: there are
good free ones), put them in your pen with one command, and Hogman makes them private.

- **A family:** photo albums, a shared calendar, recipes, the family chat, seen by nobody else.
- **Friends, clubs and teams:** your own private Facebook, with a message board, events and a
  members page.
- **A business and its customers:** a customer portal only invited customers can even reach,
  so attackers never see a login page. (Hogman isn't audited yet; wait for that before
  putting anything high-stakes behind it.)
- **A small company:** internal tools and a wiki, reachable by employees from anywhere and
  invisible to everyone else.
- **A community:** a forum or archive away from bots, trolls and drive-by strangers.
- **Your own projects:** the home server or side project, reachable from your laptop or phone
  anywhere, with real HTTPS.

**Questions people ask.**

- *Do I need to be technical?* To get a pen and invite people, no: you sign up on a web page,
  and your guests click a link and paste one command. Putting a folder or a website in the
  pen is one command too (`hogman-join share photos ~/holiday`). Bigger apps (a forum, a
  photo gallery) you install on an always-on computer, then share the same way.
- *Do my people install anything?* A small program, once; the invite link walks them through
  it on a Mac or Linux (Windows and a phone app are coming).
- *Can strangers find my pen?* No. Nothing in it has a public address.
- *Is it a VPN?* No. A VPN hides your browsing; a pen is a private place with its own sites
  and its own guest list, and your normal internet keeps working.
- *Why not just use Tailscale?* If you're technical and only want your own devices
  connected, do: Hogman is built on Tailscale's open-source pieces and runs alongside it.
  Hogman is for running a private place for a group of people: guests join from a link, the
  keeper runs the guest list from a web page, every pen has its own names, and its
  certificates stay inside the pen instead of appearing in public certificate logs.
- *Can you see what we do?* What members send each other is encrypted end to end. If we host
  your pen we can see who is in it, not what anyone says. Run your own if that's too much trust.

## How it works

Full guides, use cases and the technical details: **[hogman.network/docs](https://hogman.network/docs/)**.

**A private corner of the internet for you and your people.**

1. **Make a pen.** Sign up, and about a minute later you have your pen: your own walled-off
   space on the internet. You make the rules.
2. **Invite your people.** Send each person a link. They open it, copy the one command it shows,
   and they're in. Nobody else gets in without a link from you.
3. **Private inside, invisible outside.** Inside: your photos, your chat, your own websites,
   in any ordinary browser. Outside: strangers and bots find nothing at all.

A normal website is open to the whole internet, and bots try its login page all day. A site
in your pen can't be found from the open internet: to everyone you didn't invite, it
doesn't exist.

**Putting something in.** Once you're in, one command puts a folder or a website you're
building into the pen, with its own name and the padlock:

```text
$ ./hogman-join share photos ~/holiday --note "Summer trip photos"
$ ./hogman-join share blog 3000               # a site you're building, by its port

✓ https://blog.smith.hogman is up.
  Everyone in the pen can open it.
```

Each share is a small server device of its own, so your laptop itself still takes no
visitors, and nothing needs administrator rights or an open port. Everything shared or named
shows up in the **Sites in this pen** list on your home page (with who runs it and its
optional `--note`). Add `--background` to keep it running after the window closes;
`./hogman-join share stop blog` takes it down and frees the name. A computer that isn't in
the pen can share too: press *Get a share link* on your home page and add the link it gives you
to the end of the command.

## Under the hood

- **The network:** each pen is a private [WireGuard](https://www.wireguard.com) mesh with its own
  [Headscale](https://github.com/juanfont/headscale) (the open-source Tailscale control server);
  devices use the stock Tailscale client. Traffic is end-to-end encrypted, device to device,
  through the pen's own relay (built into its control server) only when a firewall blocks a
  direct path. Relaying, it carries only encrypted WireGuard packets and never sees what
  anyone sends.
- **Names:** a private DNS zone per pen (`smith.hogman`), answered only on the mesh. `.hogman`
  isn't a public top-level domain, so nothing in a pen exists on the open internet.
- **Padlocks (certificates):** each pen runs [step-ca](https://smallstep.com/certificates/). Its root carries
  X.509 name constraints (only the pen's zone, no IP addresses), so trusting it can't be used
  against any other site. Servers get 7-day certificates over ACME. The root key is kept
  offline, encrypted.
- **Access:** default deny. Hogman's registrar keeps the member list and writes the access
  policy. A *personal* device is a member's laptop or phone; a *server* is anything set up to
  host sites (a share, say). Members' devices can reach servers (on 443 only) and the pen's services; personal devices accept no incoming connections; a
  device that joins without an invite gets nothing. A pen carries HTTPS and nothing else: no
  ssh, no other ports (decision D-11: the best fix for a surface is to delete it).
- **Invites:** a single-use token in a link that also carries the SHA-256 fingerprint of the
  pen's root. `hogman-join` checks it before trusting anything, installs the root, and starts
  a small built-in client, running as you (never as administrator), whose local proxy carries
  only HTTPS to the pen's names.
- **The boot:** deletes all of a member's devices, revokes their keys and invites, rewrites the
  policy, and holds their names for 90 days. About two seconds.
- **Hosted pens:** five containers per pen (Headscale, registrar, step-ca, Caddy for the home
  page, and the pen's own Tailscale node, which gives its DNS, home page and CA an address on
  the mesh), its own data folder, about 75 MB of memory. Only each pen's
  control address and the relay port are exposed to the internet.

What happens when Bob opens `https://photos.smith.hogman`:

```text
1 DNS     photos.smith.hogman → 100.80.12.7   (the pen's DNS, on the mesh only)
2 policy  bob's laptop → alice's photos server: allowed (member → server)
3 tunnel  WireGuard, bob → alice, end to end (direct, else the pen's relay)
4 TLS     certificate signed by the pen's CA; hogman-join installed its root on bob's
          computer after checking its fingerprint
✓ page loads, with the padlock

A stranger typing the same address: no such name. There is nothing to reach.
```

## What you get

- **Proper names.** Every pen has its own name, and so does everything in it:
  `alice.yourpen.hogman`, `blog.alice.yourpen.hogman`. Nobody outside can look them up.
- **The padlock, without the paperwork.** Each pen runs its own certificate authority, so
  sites get HTTPS automatically. That authority can only vouch for names inside the pen.
- **Invitation only.** Single-use invite links. How someone earns one is up to you.
- **The boot.** One press and a member is back outside the fence, every device at once.
- **Walled off from everyone else.** Every pen has its own gate, names and certificate
  authority. Traffic between members is encrypted end to end; whoever keeps the pen never
  sees it. Want nobody upstream at all? Raise it on a server of your own.

## Meet the farm

<table>
  <tr>
    <td width="25%" valign="top"><img src="docs/img/keeper.jpg" alt="The Top Hog Farmer"><br><strong>THE TOP HOG</strong><br><em>That's you.</em><br>The keeper. You run the pen and decide who gets in, what they're called, and who gets the boot.</td>
    <td width="25%" valign="top"><img src="docs/img/sign.jpg" alt="The Clean Pigs Only sign"><br><strong>THE FENCE</strong><br><em>The network.</em><br>An encrypted mesh that exists only for those inside it. From outside there is nothing to see and no way in but the gate.</td>
    <td width="25%" valign="top"><img src="docs/img/clean.jpg" alt="Clean pigs in sunglasses"><br><strong>THE CLEAN PIGS</strong><br><em>Your people and their devices.</em><br>Everyone you invited, each known by name. They browse, host sites and visit each other.</td>
    <td width="25%" valign="top"><img src="docs/img/horde.jpg" alt="The filthy horde"><br><strong>THE HORDE</strong><br><em>Everything else.</em><br>Strangers, scrapers, bots. They can scream at the fence all night. Nothing inside can hear them.</td>
  </tr>
</table>

## Getting in, if you're on the list

1. **You get a link.** It carries your invitation and the fingerprint of the pen's
   certificate, so you know you're at the right gate.
2. **You run one command.** The link's page gives it to you. It checks the fingerprint,
   asks what you'd like to be called, and adds the pen's certificate to your computer.
3. **You're in.** Open your ordinary browser and go.

```text
# the command your invite page gives you: copy, paste, enter
$ curl -fsSLo hogman-join https://smith.pens.hogman.network/join/dl/hogman-join-Darwin-arm64 \
    && chmod +x hogman-join \
    && ./hogman-join 'https://smith.pens.hogman.network/join#t=(your invite)&fp=(the pen's fingerprint)'

• Checking the network at smith.pens.hogman.network
  network: smith.hogman
  its certificate matches the link
  and can only vouch for names ending in .smith.hogman

• Redeeming the invite
  Choose your name on the network: alice
  welcome, alice

✓ You're in. You are alice on smith.hogman.
```

**No Tailscale needed, and it won't fight yours.** The join tool runs its own small
connection, as you, never as administrator. It carries only HTTPS to the pen's names, and
leaves everything else on your computer, including any Tailscale of your own, alone.

**More devices:** your pen's home page has *Add a device*: a one-time link and QR code. The
new device joins as you, under your name.

## The boot

<p align="center">
  <img src="site/public/boot.webp" alt="The Top Hog Farmer kicks a pig in sunglasses clean over the fence with a spiked boot, mud flying, towards a pack of filthy boars waiting under the Clean Pigs Only sign." width="100%">
</p>

Sometimes a clean pig goes bad. One command and they're outside the fence, with their sites
gone and their names held so nobody can pretend to be them.

| Suspend | Let back in | The boot |
|:---:|:---:|:---:|
| **2.0 s** | **0.8 s** | **2.1 s** |

*Measured on a real Mac over an ordinary home network, from pressing enter to the door closing.*

## Get a pen

1. **Sign up** at [get.hogman.network](https://get.hogman.network): name your pen and
   yourself. About a minute later it's up on our server, with its own gate, names and
   certificate authority. While we test, you need a sign-up code from someone already in;
   no code, or the farm is full? Join the waiting list on the same page.
2. **Get your laptop in.** Open the link you're given on your laptop and copy one command.
3. **Let your people in.** Your pen's home page makes invite links and QR codes, and shows
   the herd: suspend anyone, or give them the boot. No server, no shell.

Same software as a self-hosted pen, so you can take your pen's folder and leave whenever you
like. Hosting your pen means we can see who's in it (not what anyone says), and could in
principle add a device to it, the same catch as Tailscale. If that's too much trust, raise
your own.

## Raise your own pen

You need a small Ubuntu 24.04 server (2 GB is plenty; about $12 a month) and a hostname
pointing at it, such as `hs.example.com`.

```bash
# 1. Install. Sets the server up (updates, Docker, firewall), installs Hogman, starts the front door.
curl -fsSL https://hogman.network/install.sh | sudo bash

# 2. Raise a pen and make yourself its keeper.
hogman-host add mypen hs.example.com
hogman-host pen mypen member add you --role owner

# 3. Get your own laptop in: open the link this prints, on the laptop.
hogman-host pen mypen device key you personal

# 4. Let the clean ones in, and show the filthy ones out.
hogman-host pen mypen invite create --note "alice, clean pig"
hogman-host pen mypen member kick gary "rolled in something"
```

The installer prints what's next: managing the server over your own Tailscale network with
SSH closed to the internet, and moving the pen's root key somewhere safe. Run the same
`curl` again later to update, then `hogman-host upgrade mypen`.

One server can hold many pens: `hogman-host add` again with another name and hostname. Each
pen is walled off from the others, in its own folder you can move to another server.

**[The keeper's guide](deploy/README.md)** goes step by step from an empty server, and covers
nightly backups, alerts on your phone, and a sign-up page if you want to host pens for others. To run a single pen by hand instead, see
[core/README.md](core/README.md).

How and why it's built this way: [DESIGN.md](DESIGN.md).

## The honest bit

- **A pen is private, not anonymous.** The keeper knows who is in the pen, their devices,
  and which pen names get looked up.
- **What the keeper can't see:** what members say to each other, or their ordinary browsing
  outside the pen.
- **Choose your Top Hog.** Joining a pen means trusting the person who runs it.

## Status

**Experimental.** Young security software, not audited, running its first public server.
Try it, break it, tell us what you find. Don't trust it with anything that matters yet.

| On tour now | Not on the bill yet |
|---|---|
| The pen: server, names, certificates, invites, the boot | Phones (the app is in the works) |
| Joining from Linux and a Mac: HTTPS only, never as administrator, alongside your own Tailscale | Windows (built, never tried) |
| Many pens on one server, kept apart | Open sign-ups for everyone |
| A one-line installer for servers; updates in under a minute | A security audit |
| A real pen live on the internet: `farm.hogman`, joined from a Mac | |
| Nightly encrypted backups, pulled to a machine you own; restore tested | |
| Alerts on your phone when the server or its backups stop | |
| Pens on our server: sign up by invitation while we test, or join the waiting list | |
| Run your pen from its home page: invites, the herd, the boot | |
| Put a folder or a website in your pen with one command (`hogman-join share`) | |
| End-to-end tests: 122 checks for a pen, 74 for a shared host | |

**Found a security problem?** Please don't open a public issue. Report it privately
with GitHub's **Security → Report a vulnerability** button on this repository.

## How it's built

Forged from good open-source steel: [Headscale](https://github.com/juanfont/headscale), the
[Tailscale](https://tailscale.com) client, [step-ca](https://smallstep.com/certificates/)
and [Caddy](https://caddyserver.com), plus three pieces of our own:

| Piece | What it does |
|---|---|
| [`core/registrar`](core/registrar) | The ledger: members, invites, devices, names, the boot. Writes the pen's access rules and DNS. |
| [`core/join`](core/join) | `hogman-join`: verifies, trusts, enrols and joins, on macOS, Linux and Windows. |
| [`deploy/hogman-host`](deploy/hogman-host) | Runs many pens on one server behind a shared front door. |

## License

Hogman's code is free software under the [GNU Affero General Public License v3.0](LICENSE).
You may use, study, change and share it. If you run a changed version as a service for
others, you must offer them your changes under the same license.

The artwork (the paintings, the logo, and the crops of them in `docs/img/`) is not covered by
that license. All rights reserved.

<p align="center"><strong>Keep a clean pen.</strong></p>
