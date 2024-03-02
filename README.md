# PKI tool for lazy people

This is CLI tool to manipulate certificates and private keys in single directory, most notably
it can create root CA, intermediate CA and leaf certificates (+ private keys), quite easily.

It exists because using `openssl` to achieve something similar is waste of time (or am I the only one using it wrong way?).

This tool can do only very basic things, mainly to support test activities around PKI use cases (read _I need TLS cert of some sort_).

## Example

I want root CA, intermediate CA and 2 leaf certs for my web servers.

- root CA
    ```shell
     ./dist/pkitool create ca --years 10 --alias rootCA --subject-common-name "Root of all evil" --subject-organization "My evil organization"
    ```
   Now you got `rootCA.pem` and `rootCA.key` in current directory. Nice.

- intermediate CA
    ```shell
     pkitool create ca --years 5 --intermediate --parent rootCA --alias imCA --subject-common-name "evil child" --subject-organization "My evil organization"
    ```

- leaf 1
    ```shell
     pkitool create leaf --years 2 --parent imCA --alias server1 --subject-common-name "server1" --subject-organization "My evil organization"
    ```

- leaf 2
    ```shell
     pkitool create leaf --years 2 --parent imCA --alias server2 --subject-common-name "server2" --subject-organization "My evil organization"
    ```

Wanna SANs? just append `--dns-san server1.acme.tld` or `--ip-san 192.168.10.31` when creating leaf certificate.

### Show me what was created

```shell
pkitool list
+--------------------------------+--------------------------------+-------------------------------+
|            SUBJECT             |             ISSUER             |           VALID TO            |
+--------------------------------+--------------------------------+-------------------------------+
| CN=evil child,O=My evil        | CN=Root of all evil,O=My evil  | 2029-03-02 13:28:37 +0000 UTC |
| organization                   | organization                   |                               |
| CN=Root of all evil,O=My evil  | CN=Root of all evil,O=My evil  | 2034-03-02 13:28:34 +0000 UTC |
| organization                   | organization                   |                               |
| CN=server1,O=My evil           | CN=evil child,O=My evil        | 2026-03-02 13:28:43 +0000 UTC |
| organization                   | organization                   |                               |
| CN=server2,O=My evil           | CN=evil child,O=My evil        | 2026-03-02 13:31:59 +0000 UTC |
| organization                   | organization                   |                               |
+--------------------------------+--------------------------------+-------------------------------+
```

### More detail, please

```shell
pkitool show --alias server2
+--------------------------+---------------------------------------------------+
|         PROPERTY         |                       VALUE                       |
+--------------------------+---------------------------------------------------+
| Basic constraints valid? | true                                              |
| Ext. key usage           | ExtKeyUsageClientAuth,ExtKeyUsageServerAuth       |
| Is CA?                   | false                                             |
| Issuer                   | CN=evil child,O=My evil                           |
|                          | organization                                      |
| Key usage                | KeyUsageDigitalSignature,KeyUsageDataEncipherment |
| Public exponent          | 65537                                             |
| Serial                   | 0                                                 |
| Subject                  | CN=server2,O=My evil                              |
|                          | organization                                      |
| Valid from               | 2024-03-02 13:31:59 +0000 UTC                     |
| Valid to                 | 2026-03-02 13:31:59 +0000 UTC                     |
+--------------------------+---------------------------------------------------+
```
