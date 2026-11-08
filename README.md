# keystore-certificate-ssh-updater

## Command

### Single
#### User password Authentication 
<pre>url=https://github.com host=127.0.0.1 port=22 user=user password=password     keytool=/usr/bin/keytool keystore=/etc/ssl/certs/java/cacerts storepass=c******t</pre>
#### Public Key Authentication
<pre>url=https://github.com host=127.0.0.1 port=22 user=user publicKey=publick.ppk keytool=/usr/bin/keytool keystore=/etc/ssl/certs/java/cacerts storepass=c******t</pre>

### Configuration File
<pre>url=https://github.com config=KeystoreCertificateSshUpdater.xml/</pre>

<pre>
&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;
&lt;configs&gt;
	&lt;config host=&quot;127.0.0.1&quot; port=&quot;2222&quot; user=&quot;user&quot; password=&quot;password&quot;
		keytool=&quot;/usr/lib/jvm/jdk-25-oracle-x64/bin/keytool&quot;&gt;
		&lt;keystores&gt;
			&lt;keystore path=&quot;/etc/ssl/certs/java/cacerts&quot; password=&quot;c******t&quot; /&gt;
		&lt;/keystores&gt;
	&lt;/config&gt;
&lt;/configs&gt;
</pre>
<pre>
&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;
&lt;configs&gt;
	&lt;config host=&quot;127.0.0.1&quot; port=&quot;2222&quot; user=&quot;user&quot; publicKey=&quot;publicKey.ppk&quot;
		keytool=&quot;/usr/lib/jvm/jdk-25-oracle-x64/bin/keytool&quot;&gt;
		&lt;keystores&gt;
			&lt;keystore path=&quot;/etc/ssl/certs/java/cacerts&quot; password=&quot;c******t&quot; /&gt;
		&lt;/keystores&gt;
	&lt;/config&gt;
&lt;/configs&gt;
</pre>

## GUI

Double click the jar under <b>Microsoft Windows</b> or <b>Apple MacOS</b>.

## Default Key Store Password

<a href="https://docs.oracle.com/en/java/javase/27/docs/specs/man/keytool.html">The keytool Command</a>
<img width="1264" height="34" alt="image" src="https://github.com/user-attachments/assets/669d0d44-50c1-418a-98d1-da54aa2258ae" />

