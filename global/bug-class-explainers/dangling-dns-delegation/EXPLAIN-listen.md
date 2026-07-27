PROMPT — read this, then do what it says. Do not read this prompt out loud.

I am going to LISTEN to your answer, not read it. That changes everything about how you should
write it.

No formatting of any kind. No markdown. No headings. No bullet points. No numbered lists. No
tables. No code blocks. No asterisks, hashes, backticks, arrows, or bullet characters. No URLs.
No file paths. Nothing that only makes sense to the eye — if it would be read aloud as a symbol
or a piece of punctuation salad, leave it out entirely.

Write in plain spoken prose, in full sentences and ordinary paragraphs, the way a person actually
talks. Where the source material below uses a technical term, say it the way you would say it out
loud and explain it in passing the first time it comes up. If you must refer to something that
would normally be written as code or an address, describe it in words instead.

Turn the material below into a natural two-speaker conversation, roughly eight to ten minutes when
spoken. One speaker is curious and asks the questions a smart person new to the topic would
genuinely ask. The other explains clearly, without jargon, and never talks down or pads. Let the
curious one interrupt and push back where a real person would.

No sound effects, no music, no stage directions, no speaker labels beyond what is needed to tell
the two voices apart.

The goal is that I finish listening and actually understand the idea well enough to explain it to
someone else.

Here is the material.

---

There is a class of security problem that comes from something very ordinary: a company moves
house and forgets to cancel their mail forwarding.

To understand it, you first need to understand how a web address actually finds a website. When
you type an address into your browser, your computer does not magically know where that website
lives. It asks a directory service. That directory is called the domain name system, and its job
is to translate a name a human can remember into a location a machine can reach.

Most of the time the directory gives back an address, and that is the end of it. But there is
another kind of entry the directory can hold. Instead of saying here is the address, it can say
do not ask me, ask them. It is a forwarding instruction. In the industry this is called an alias
record, and it points one name at another name.

Now, why would anyone want that? Because almost nobody runs their own web servers any more. A
company will build a small site and put it on a hosting platform — one of the big services that
runs websites for millions of customers. That platform gives them a location on its own system.
The company then puts a forwarding instruction in the directory that says, when someone asks for
this part of my domain, send them to my little corner of that platform.

That works well. The platform handles the servers, the security certificates, all of it. The
company just points at it.

Here is where it goes wrong.

Companies change. They rebrand. They retire old products. They migrate to a different platform.
And when they do, somebody tears down the old site on the hosting platform. That part gets done,
because it costs money to keep running and somebody notices the bill.

But the forwarding instruction in the directory costs nothing. Nobody gets a bill for it. So it
sits there, quietly, pointing at a corner of a platform that is now empty.

Think of it as a physical address. You tell the post office to forward everything for your home
to Suite Four Hundred in a large office building downtown. Later you move out of Suite Four
Hundred. You cancel the lease. But you never cancel the forwarding.

Your mail still goes to that building. The building still has a Suite Four Hundred. It is just
empty now.

And here is the problem. Suite Four Hundred is available to rent.

If somebody else rents that suite, your mail starts arriving at their desk. They did not break
into anything. They did not steal anything. They rented an empty office, and your own forwarding
instruction delivered your mail to them.

That is what this class of bug is. The technical name is a dangling delegation, or a subdomain
takeover. The forwarding instruction is dangling because the thing it points at is gone.

You can see it from the outside without doing anything clever. You look up the forwarding
instruction and see it points at a hosting platform. Then you visit the address in a browser, and
the platform itself tells you the truth. It says, in plain language, that no site is configured
here. Different platforms word it differently. One says site not found. Another says deployment
not found. But they all mean the same thing — the directory sent me here, and there is nothing
here.

Now, why does this actually matter? Because of what an attacker gets if they can rent that empty
suite.

They get to serve whatever they want from an address that genuinely belongs to the company. Not a
lookalike address with a misspelling. Not something that only resembles the real thing. The
actual address, owned by the actual company.

And because the hosting platform automatically issues security certificates for whatever is
hosted on it, the attacker gets a real, valid certificate too. The padlock in the browser is
genuine.

Stop and think about what that defeats. Everything a careful person is taught to check. Is the
address right? Yes, it is. Is there a padlock? Yes, and a real one. Is this the company's own
domain? It genuinely is.

Every one of those checks passes, and the page is still controlled by an attacker.

There is a second consequence that is less obvious but often worse. Web browsers share certain
pieces of stored information across all the addresses under one domain. Login tokens, session
identifiers, preferences. If an attacker controls any address under that domain, depending on how
those tokens were configured, they may be able to read them. So a forgotten forwarding
instruction on a minor, unused part of the domain can reach back and touch the main service.

It gets worse depending on what the abandoned address is named. Names carry meaning. If the
forgotten address was for a marketing page, that is bad. If it was named something to do with
logging in, that is considerably worse, because the people who end up there are precisely the
people about to type a password.

Now here is the part that separates a careful researcher from a careless one, and it is the most
important thing in this whole explanation.

Finding that the suite is empty is not the same as proving you can rent it.

Modern hosting platforms learned about this problem years ago. Most of them now require you to
prove you control a domain before they will let you attach it to your account. They do that by
asking you to add a specific record to your directory entry — something only the real owner could
do.

So when you find one of these, what you have genuinely proven is that the forwarding instruction
points at nothing. What you have not proven is that anyone else could step in and take it.

Those are two different claims and only the first one is supported by what you can see from
outside.

You could go and find out. You could try to register that name on the platform. But that means
performing an action on the hosting platform's systems, and that platform is a completely
different company that never agreed to be tested. So a careful researcher does not do it. They
report exactly what they observed, they state clearly what they did not establish, and they let
the company check their own account records to answer the remaining question.

This restraint is not weakness. It is the difference between a report that gets taken seriously
and one that gets dismissed. A reviewer reading a claim of a confirmed takeover, who then notices
the takeover was never actually demonstrated, stops trusting everything else in the report. A
reviewer who sees the researcher draw that line themselves, before being asked, reads the rest
with confidence.

The fix, by the way, is trivial. Delete the forwarding instruction, or point it at something that
actually exists. It takes about a minute. The difficulty is never in the fixing — it is entirely
in the noticing, because nothing breaks, nothing alerts, and nobody gets a bill for a directory
entry pointing into empty space.

Which is why these sit around for years.

One last thought about how you find them. Looking at a single abandoned address tells you
somebody made a mistake. Looking at several, and noticing they all trace back to the same event —
a rebrand, a migration, a product retirement — tells you something much more useful. It says the
cleanup was incomplete, and it suggests there are probably more that have not been found yet.
That framing is far more valuable to the company than a list of individual broken addresses,
because it points them at the process that failed rather than just the symptoms.

And here is how this connects to the wider picture. The same shape shows up everywhere in
security. Something gets decommissioned, and the pointer to it survives. An old server is retired
but the firewall rule allowing traffic to its address remains. An employee leaves but their access
token stays valid. A service is shut down but the credential it used is never revoked. In every
case the valuable thing was removed and the reference to it was not, and the danger lives entirely
in that surviving reference. Once you learn to look for the gap between what was decommissioned
and what still points at it, you start seeing this pattern in places that have nothing to do with
web addresses at all.
