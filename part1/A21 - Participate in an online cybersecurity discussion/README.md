
@sec_practitioner_maya 

Passwordless auth (passkeys, biometrics, FIDO2) is a genuine improvement. Phishing credentials becomes nearly impossible when there's no password to steal. I've rolled it out at two orgs — adoption friction is the main hurdle, not the security model.

@redteam_carlos 

Agreed on phishing resistance, but let's not pretend it's bulletproof. Device compromise becomes the new attack vector. If I own your phone or laptop, your passkey is mine. The threat model shifts — it doesn't disappear.

@phoenix_infosec 

Carlos raises a valid point. The risk surface changes shape rather than shrinking. That said, I'd argue it's still a net improvement — credential stuffing attacks (which account for a huge % of breaches) become irrelevant. The question is whether orgs have solid device management (MDM, remote wipe) to compensate.

@compliance_nadia 

From a compliance angle, passwordless introduces complexity around audit trails. How do you prove who authenticated if the factor is "the device"? FIDO2 attestation helps, but most compliance frameworks haven't caught up. SOC 2 auditors still ask for password policies.

@phoenix_infosec

Nadia — that's a real gap. I've seen orgs implement passkeys for end users but keep passwords internally for service accounts, which creates a hybrid mess. Identity governance tools need to evolve alongside the auth methods.

@devops_tariq 

What about CI/CD pipelines and machine-to-machine auth? Passkeys are great for humans but we're still relying on API keys and secrets for automation. That's where I see the real exposure — developers hardcoding secrets in repos.

@sec_practitioner_maya

Tariq — 100%. Secrets management (Vault, AWS Secrets Manager, etc.) is the passwordless equivalent for machines. The human-facing and machine-facing problems need separate solutions. Bundling them into one conversation muddies the water.

@phoenix_infosec

Good thread. My takeaway: passwordless is directionally correct for human auth, but it requires a broader ecosystem shift — device hygiene, secrets management for non-human identities, and updated compliance frameworks. It's not a silver bullet, it's one piece of a mature security posture.

