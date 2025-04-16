certbot-dns-buddy
=================

Buddy DNS Authenticator plugin for Certbot

This plugin automates the process of completing a ``dns-01`` challenge by
creating, and subsequently removing, TXT records using the Buddy Rest API.

Issue a token
--------------------

In your Buddy account create personal access token with scopes:

- WORKSPACE
- ZONE_WRITE
- ZONE_READ

Installation
------------

.. code-block:: bash

    pip install certbot-dns-buddy

Usage
-----

Via environment variable
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

  export BUDDY_TOKEN=xxx
  # pass workspace url domain
  export BUDDY_WORKSPACE=yyy
  # if you want to use different region than US
  export BUDDY_BASE_URL=https://api.eu.buddy.works
  certbot certonly \
     --authenticator dns-buddy \
     --agree-tos \
     -d 'foo.bar'

Via INI file
^^^^^^^^^^^^^^^^^^^^^^^^

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).

===================================  ==========================================

``--authenticator dns-buddy``        select the authenticator plugin (Required)
``--dns-buddy-credentials``          Buddy Token credentials
                                     INI file. (Required)
===================================  ==========================================

An example ``credentials.ini`` file:

.. code-block:: ini

   dns_buddy_token = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   dns_buddy_workspace = YYY
   dns_buddy_base_url = https://api.eu.buddy.works

To start using DNS authentication for Buddy, pass the following arguments on certbot's command line:

.. code-block:: bash

  certbot certonly \
    --authenticator dns-buddy \
    --dns-buddy-credentials <path to file> \
    --agree-tos \
    -d 'foo.bar'


Automatic renewal
-----------------

By default, certbot installs a service that periodically renews its
certificates automatically. In order to do this, the command must know the API
key, otherwise it will fail silently.

In order to enable automatic renewal for your wildcard certificates, you will
need to edit ``/lib/systemd/system/certbot.service``. In there, add the
following line in ``Service``, with <YOUR_API_TOKEN> replaced with your actual
token:

.. code-block:: bash

   Environment="BUDDY_TOKEN=<YOUR_API_TOKEN>"
   Environment="BUDDY_WORKSPACE=<YOUR_API_TOKEN>"