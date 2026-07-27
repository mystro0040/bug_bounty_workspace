PROMPT. Read this and follow it. Do not read this prompt out loud and do not refer to it.

What you write is going to be turned into speech and listened to. It will never be read on a
screen. That one fact governs everything below.

Strip out all formatting. Not less of it. None of it. No markdown, no headings, no titles, no
bullet points, no numbered lists, no tables, no code blocks, no bold, no italics, no asterisks,
hashes, backticks, underscores, angle brackets, arrows, or bullet characters. No dashes used as
punctuation. No parentheses. No quotation marks around technical terms. No colon introducing a
list. No web addresses, no file paths, no email addresses.

The reason is simple. Formatting either gets read out as literal junk, so the listener hears
asterisk asterisk and hash hash in the middle of a sentence, or it gets silently dropped and the
sentence collapses into something that no longer makes sense. Either way it sounds stupid. Any
sentence that needs a symbol in order to work is a sentence that has to be rewritten as words.

Write every number, address, and symbol out in words, the way a person actually says them. One
hundred and twenty seven dot zero dot zero dot one. Port four four three. Expand every acronym
into ordinary words the first time it appears and then keep using the words. Say domain name
system rather than the three letters. Say server side request forgery rather than the initials.
If something would normally be written as code or as an address, describe it in words instead.

One narrator throughout. No dialogue, no second speaker, no interviewer, no character names, no
stage directions, no sound effects. Write continuous explanatory prose in ordinary paragraphs,
calm and declarative, the way a good instructor talks when they are explaining something properly
and are not in a hurry.

Explain each technical term in passing the first time it comes up, inside the same sentence,
without stopping to define it formally.

Do not number the sections and do not announce them. A numbered framing is acceptable if it falls
out naturally, but nothing here depends on one, so do not invent one.

Aim for roughly eight to ten minutes when spoken.

The goal is that after listening once, having never seen any text, the listener understands the
idea well enough to explain it to somebody else.

Here is the material.

---

This lesson is about a class of security problem that comes from something completely ordinary. A
company moves out of a building and forgets to cancel its mail forwarding.

To understand it you first need to understand how a web address finds a website. When a person
types an address into a browser, the computer does not already know where that website lives. It
asks a directory service. That directory is called the domain name system, and its only job is to
translate a name a human can remember into a location a machine can reach.

Most of the time the directory hands back an address and that is the end of it. But the directory
can hold another kind of entry. Instead of saying here is the address, it can say do not ask me,
ask them. It is a forwarding instruction. In the industry this is called an alias record, and it
points one name at another name.

There is a good reason companies use these. Almost nobody runs their own web servers any more. A
company builds a small site and puts it on a hosting platform, one of the large services that runs
websites for millions of customers. The platform gives the company a location on its own system.
The company then puts a forwarding instruction in the directory saying that when somebody asks for
this part of my domain, send them to my little corner of that platform. That arrangement works
well. The platform handles the servers and the security certificates and everything else. The
company simply points at it.

Here is where it goes wrong. Companies change. They rebrand. They retire old products. They
migrate from one platform to another. When they do, somebody tears down the old site on the
hosting platform. That part reliably gets done, because a running site costs money every month and
somebody eventually notices the bill.

The forwarding instruction in the directory costs nothing. Nobody is ever billed for it. So it
sits there quietly, pointing at a corner of a platform that is now empty.

Think about it as a physical address. You tell the post office to forward everything for your home
to Suite Four Hundred in a large office building downtown. Later you move out of Suite Four
Hundred and you cancel the lease. But you never cancel the forwarding. Your mail still goes to
that building, and the building still has a Suite Four Hundred. It is just empty now. And Suite
Four Hundred is available to rent. If somebody else rents that suite, your mail starts arriving on
their desk. They did not break into anything and they did not steal anything. They rented an empty
office, and your own forwarding instruction delivered your mail to them.

That is exactly what this class of bug is. The technical name for it is a dangling delegation, or
a subdomain takeover. The forwarding instruction is described as dangling because the thing it
points at is gone.

You can see the whole thing from the outside without doing anything clever. You look up the
forwarding instruction and you see that it points at a hosting platform. Then you visit the
address in a browser, and the platform itself tells you the truth. It says in plain language that
no site is configured here. Different platforms word it differently. One of them says site not
found. Another says deployment not found. They all mean the same thing. The directory sent me
here, and there is nothing here.

The reason this matters is what an attacker gets if they can rent that empty suite. They get to
serve whatever they want from an address that genuinely belongs to the company. Not a lookalike
address with a misspelling in it. Not something that merely resembles the real thing. The actual
address, owned by the actual company.

And because the hosting platform automatically issues security certificates for whatever gets
hosted on it, the attacker receives a real and valid certificate as well. The padlock in the
browser is genuine.

It is worth stopping to think about what that defeats. It defeats everything a careful person is
taught to check. Is the address correct. It is. Is there a padlock. There is, and it is a real
one. Is this the company's own domain. It genuinely is. Every one of those checks passes, and the
page is still under the control of an attacker.

There is a second consequence that is less obvious and often worse. Web browsers share certain
pieces of stored information across all of the addresses that sit under a single domain. Login
tokens, session identifiers, saved preferences. If an attacker controls any address under that
domain, then depending on how those tokens were configured, the attacker may be able to read them.
So a forgotten forwarding instruction on a minor and completely unused part of the domain can
reach back and touch the main service.

How bad it gets also depends on what the abandoned address was named, because names carry meaning.
If the forgotten address served a marketing page, that is bad. If it was named something to do
with logging in, that is considerably worse, because the people who end up there are precisely the
people who are about to type a password.

Now comes the part that separates a careful researcher from a careless one, and it is the single
most important idea in this whole explanation. Finding that the suite is empty is not the same as
proving that you could rent it.

Modern hosting platforms learned about this problem years ago. Most of them now require you to
prove that you control a domain before they will let you attach that domain to your account. They
do it by asking you to add a specific record to your directory entry, something only the genuine
owner could do.

So when you find one of these, what you have actually proven is that the forwarding instruction
points at nothing. What you have not proven is that anybody else could step in and take it over.
Those are two different claims, and only the first one is supported by what can be seen from the
outside.

You could go and find out. You could try to register that name on the hosting platform. But doing
that means performing an action on the hosting platform's own systems, and that platform is a
separate company that never agreed to be tested. So a careful researcher does not attempt it. They
report exactly what they observed, they state clearly what they did not establish, and they let
the company check its own account records to answer the remaining question.

That restraint is not weakness. It is the difference between a report that is taken seriously and
one that is dismissed. A reviewer who reads a claim of a confirmed takeover, and then notices that
the takeover was never actually demonstrated, stops trusting everything else in the report. A
reviewer who sees the researcher draw that line themselves, before anybody asked them to, reads
the rest of it with confidence.

The fix is trivial. Delete the forwarding instruction, or point it at something that actually
exists. It takes about a minute. The difficulty is never in the fixing. It is entirely in the
noticing, because nothing breaks, nothing raises an alert, and nobody is ever billed for a
directory entry that points into empty space. That is why these sit around for years.

There is one more thing worth understanding about how they are found. Looking at a single
abandoned address tells you that somebody made a mistake. Looking at several of them, and
noticing that they all trace back to the same event, a rebrand or a migration or a product being
retired, tells you something far more useful. It says the cleanup was incomplete, and it suggests
there are probably more that nobody has found yet. That framing is much more valuable to the
company than a list of individual broken addresses, because it points them at the process that
failed rather than at the symptoms.

Finally, here is how this connects to the wider picture. The same shape turns up everywhere in
security. Something gets decommissioned and the pointer to it survives. An old server is retired
but the firewall rule that allows traffic to its address remains in place. An employee leaves but
their access token stays valid. A service is shut down but the credential it used is never
revoked. In every one of those cases the valuable thing was removed and the reference to it was
not, and the danger lives entirely inside that surviving reference. Once you learn to look for the
gap between what was decommissioned and what still points at it, you start seeing this pattern in
places that have nothing to do with web addresses at all.
