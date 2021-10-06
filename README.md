# p2op5

PUPPETDB->OP5 API Lambda Function

This function runs periodically, polling PuppetDB for new nodes that are enrolled within the
ee-op5 Puppet environment. It then mines metadata from those nodes to determine which packages
are installed, and registers the nodes with the OP5 API, including appropriate hostgroups
based on the discovered profile.

Sensitive information is stored in Hashicorp Vault and accessed using the AWS IAM role-based
authentication mechanism. The exact calls to Vault are abstracted by the use of a Lambda layer
that is managed in another Terraform workspace. The layer reference can be removed if desired,
but resources will then need to be hard-coded into this function, or accessed securely via
other means.
