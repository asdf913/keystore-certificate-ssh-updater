package org.apache.sshd.client;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.rmi.RemoteException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.function.FailableBiConsumer;
import org.apache.commons.lang3.function.FailableBiFunction;
import org.apache.commons.lang3.function.FailableConsumer;
import org.apache.commons.lang3.function.FailableFunction;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionCreator;
import org.apache.sshd.common.auth.BasicCredentialsImpl;
import org.apache.sshd.common.auth.BasicCredentialsProvider;
import org.apache.sshd.common.auth.PasswordHolder;
import org.apache.sshd.common.auth.UsernameHolder;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceLoader;
import org.apache.sshd.common.future.VerifiableFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.putty.PuttyKeyUtils;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.d2ab.function.ObjIntPredicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.google.common.net.HostAndPort;

import io.github.toolfactory.narcissus.Narcissus;

public class KeyStoreCertificateSshUpdater {

	private static final Logger LOG = LoggerFactory.getLogger(KeyStoreCertificateSshUpdater.class);

	private static final String DELEGATE = "delegate";

	private static final String VALUE = "value";

	private static final String PASSWORD = "password";

	public static void main(final String[] args) throws Exception {
		//
		final List<Method> ms = collect(
				filter(testAndApply(Objects::nonNull, File.class.getDeclaredMethods(), Arrays::stream, null),
						m -> Boolean.logicalAnd(Objects.equals(getName(m), "createTempFile"),
								Arrays.equals(getParameterTypes(m), new Class<?>[] { String.class, String.class }))),
				Collectors.toList());
		//
		if (size(ms) > 1) {
			//
			throw new RuntimeException();
			//
		} // if
			//
		final File tempFile = cast(File.class,
				testAndApply(x -> isStatic(x), testAndApply(x -> size(x) == 1, ms, x -> get(x, 0), null),
						x -> Narcissus.invokeStaticMethod(x, nextAlphabetic(RandomStringUtils.secure(), 3), null),
						null));
		//
		deleteOnExit(tempFile);
		//
		try (final SshClient sshClient = SshClient.setUpDefaultClient()) {
			//
			start(sshClient);
			//
			final Map<String, String> map = toMap(args);
			//
			if (containsKey(map, "config")) {
				//
				final Document document = testAndApply(
						x -> and(x, KeyStoreCertificateSshUpdater::exists, KeyStoreCertificateSshUpdater::isFile),
						testAndApply(Objects::nonNull, get(map, "config"), File::new, null),
						x -> parse(newDocumentBuilder(DocumentBuilderFactory.newInstance()), x), null);
				//
				final XPath xp = newXPath(XPathFactory.newInstance());
				//
				final NodeList nodeList1 = cast(NodeList.class,
						evaluate(xp, "/*/config", document, XPathConstants.NODESET));
				//
				NodeList nodeList2 = null;
				//
				Node node1, node2 = null;
				//
				NamedNodeMap attributes = null;
				//
				Config config = null;
				//
				MessageDigest md = null;
				//
				final String url = get(map, "url");
				//
				for (int i = 0; i < getLength(nodeList1); i++) {
					//
					if ((node1 = item(nodeList1, i)) == null) {
						//
						continue;
						//
					} // if
						//
					(config = new Config()).hostAndPort = HostAndPort.fromParts(
							getNodeValue(getNamedItem(attributes = getAttributes(node1), "host")),
							NumberUtils.toInt(getNodeValue(getNamedItem(attributes, "port")), 22));
					//
					config.basicCredentialsProvider = new BasicCredentialsImpl(
							getNodeValue(getNamedItem(attributes, "user")),
							getNodeValue(getNamedItem(attributes, PASSWORD)));
					//
					config.publicKey = testAndApply(Objects::nonNull,
							getNodeValue(getNamedItem(attributes, "publicKey")), File::new, null);
					//
					config.keytool = getNodeValue(getNamedItem(attributes, "keytool"));
					//
					nodeList2 = cast(NodeList.class, evaluate(xp, "*/keystore", node1, XPathConstants.NODESET));
					//
					for (int j = 0; j < getLength(nodeList2); j++) {
						//
						if ((node2 = item(nodeList2, j)) == null) {
							//
							continue;
							//
						} // if
							//
						config.keyStorePathPassword = Pair.of(
								getNodeValue(getNamedItem(attributes = getAttributes(node2), "path")),
								getNodeValue(getNamedItem(attributes, PASSWORD)));
						//
						perform(sshClient, config, tempFile, url,
								md = ObjectUtils.getIfNull(md, () -> getMessageDigest("SHA-1")), LOG);
						//
					} // for
						//
				} // for
					//
			} else {
				//
				final Config config = new Config();
				//
				config.hostAndPort = testAndApply(Objects::nonNull, get(map, "host"),
						x -> HostAndPort.fromParts(x, NumberUtils.toInt(get(map, "port"), 22)), null);
				//
				config.basicCredentialsProvider = new BasicCredentialsImpl(get(map, "user"), get(map, PASSWORD));
				//
				config.publicKey = testAndApply(Objects::nonNull, get(map, "publicKey"), File::new, null);
				//
				config.keytool = get(map, "keytool");
				//
				config.keyStorePathPassword = Pair.of(get(map, "keystore"), get(map, "storepass"));
				//
				perform(sshClient, config, tempFile, get(map, "url"), getMessageDigest("SHA-1"), LOG);
				//
			} // if
				//
		} // try
			//
	}

	private static boolean isStatic(final Member instance) {
		return instance != null && Modifier.isStatic(instance.getModifiers());
	}

	private static Class<?>[] getParameterTypes(final Method instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Stream<Field> stream = testAndApply(Objects::nonNull,
				testAndApply(Objects::nonNull, getClass(instance), Narcissus::getDeclaredFields, null), Arrays::stream,
				null);
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(stream, f -> Objects.equals(getName(f), "parameterTypes")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getParameterTypes() : null;
		//
	}

	private static MessageDigest getMessageDigest(final String name) {
		//
		final List<Method> ms = collect(
				filter(testAndApply(Objects::nonNull, MessageDigest.class.getDeclaredMethods(), Arrays::stream, null),
						m -> Boolean.logicalAnd(Objects.equals(getName(m), "getInstance"),
								Arrays.equals(getParameterTypes(m), new Class<?>[] { String.class }))),
				Collectors.toList());
		//
		if (size(ms) > 1) {
			//
			throw new RuntimeException();
			//
		} else if (ms == null || ms.isEmpty()) {
			//
			return null;
			//
		} // if
			//
		final Method m = testAndApply(x -> size(x) == 1, ms, x -> get(x, 0), null);
		//
		if (m == null) {
			//
			return null;
			//
		} else if (isStatic(m)) {
			//
			final Field field = testAndApply(y -> size(y) == 1,
					collect(filter(
							stream(testAndApply(Objects::nonNull, getClass(name), FieldUtils::getAllFieldsList, null)),
							f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
					y -> get(y, 0), null);
			//
			return cast(MessageDigest.class,
					name != null && (field == null || Narcissus.getField(name, field) != null)
							? Narcissus.invokeStaticMethod(m, name)
							: null);
			//
		} // if
			//
		throw new RuntimeException();
		//
	}

	private static Node item(final NodeList instance, final int index) {
		return instance != null ? instance.item(index) : null;
	}

	private static int getLength(final NodeList instance) {
		return instance != null ? instance.getLength() : 0;
	}

	private static XPath newXPath(final XPathFactory instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "_featureManager")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.newXPath() : null;
		//
	}

	private static void deleteOnExit(final File instance) {
		if (instance != null && instance.getPath() != null) {
			instance.deleteOnExit();
		}
	}

	private static String getNodeValue(final Node instance) {
		return instance != null ? instance.getNodeValue() : null;
	}

	private static Node getNamedItem(final NamedNodeMap instance, final String name) {
		return instance != null ? instance.getNamedItem(name) : null;
	}

	private static NamedNodeMap getAttributes(final Node instance) {
		return instance != null ? instance.getAttributes() : null;
	}

	private static DocumentBuilder newDocumentBuilder(final DocumentBuilderFactory instance)
			throws ParserConfigurationException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "fSecurityManager")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.newDocumentBuilder() : null;
		//
	}

	private static Document parse(final DocumentBuilder instance, final File file) throws SAXException, IOException {
		return instance != null && file != null && file.getPath() != null ? instance.parse(file) : null;
	}

	private static Object evaluate(final XPath instance, final String string, final Object object, final QName qName)
			throws XPathExpressionException {
		return instance != null && object != null ? instance.evaluate(string, object, qName) : null;
	}

	private static boolean containsKey(final Map<?, ?> instance, final Object key) {
		return instance != null && instance.containsKey(key);
	}

	private static class Config {

		private HostAndPort hostAndPort = null;

		private BasicCredentialsProvider basicCredentialsProvider = null;

		private File publicKey = null;

		private String keytool = null;

		private Entry<String, String> keyStorePathPassword = null;

		private String getKeytool() {
			return keytool;
		}

		private static String getKeytool(final Config instnace) {
			return instnace != null ? instnace.getKeytool() : null;
		}

	}

	private static void perform(final SshClient sshClient, final Config config, final File tempFile, final String url,
			final MessageDigest md, final Logger logger) throws Exception {
		//
		final String algorithm = getAlgorithm(md);
		//
		final int length = Math.max(StringUtils.length(algorithm), 9);
		//
		final HostAndPort hostAndPort = config != null ? config.hostAndPort : null;
		//
		final String host = getHost(hostAndPort);
		//
		final int port = hostAndPort != null && hostAndPort.hasPort() ? hostAndPort.getPort() : 22;
		//
		final BasicCredentialsProvider basicCredentialsProvider = config != null ? config.basicCredentialsProvider
				: null;
		//
		final Entry<String, String> keyStorePathPassword = config != null ? config.keyStorePathPassword : null;
		//
		final String file = getKey(keyStorePathPassword);
		//
		try (final ClientSession clientSession = testAndApply(
				(a, b) -> Boolean.logicalAnd(a != null, StringUtils.isNotEmpty(b)),
				getUsername(basicCredentialsProvider), host,
				(a, b) -> getSession(verify(connect(sshClient, a, b, port))), null)) {
			//
			testAndAccept(Objects::nonNull, getPassword(basicCredentialsProvider),
					x -> addPasswordIdentity(clientSession, x));
			//
			testAndAccept(Objects::nonNull,
					testAndApply(x -> size(x) == 1,
							testAndApply(x -> Boolean.logicalAnd(exists(x), isFile(x)),
									config != null ? config.publicKey : null,
									x -> loadKeyPairs(PuttyKeyUtils.DEFAULT_INSTANCE, null, toPath(x), null), null),
							x -> new ArrayList<>(x).get(0), null),
					x -> addPublicKeyIdentity(clientSession, x));
			//
			try (final SftpClient sftpClient = isSuccess(verify(auth(clientSession)))
					? createSftpClient(SftpClientFactory.instance(), clientSession)
					: null; final InputStream is = read(sftpClient, file)) {
				//
				testAndAccept(
						(a, b) -> Boolean.logicalAnd(b != null,
								and(a, KeyStoreCertificateSshUpdater::exists, KeyStoreCertificateSshUpdater::canWrite)),
						tempFile, is, (a, b) -> FileUtils.writeByteArrayToFile(a, IOUtils.toByteArray(b)));
				//
				final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
				//
				final String storepass = getValue(keyStorePathPassword);
				//
				try (final InputStream is2 = testAndApply(
						x -> x != null && x.getPath() != null && x.exists() && x.isFile() && x.length() > 0, tempFile,
						FileInputStream::new, null)) {
					//
					load(keyStore, is2, toCharArray(storepass));
					//
				} // try
					//
				final Certificate certificate = getCertfiicate(url);
				//
				final byte[] encoded = getEncoded(certificate);
				//
				final String format = "{}={}";
				//
				info(logger, format, StringUtils.rightPad(algorithm, length),
						toUpperCase(addCharacter(
								testAndApply(Objects::nonNull, digest(md, encoded), Hex::encodeHexString, null), 2,
								':')));
				//
				if (contains(keyStore, encoded)) {
					//
					info(logger, "Certificate is found.");
					//
				} else {
					//
					try {
						//
						final String dateFormat = "+%Y%m%d_%H%M%S";
						//
						if (Objects.equals(
								StringUtils.trim(executeRemoteCommand(clientSession,
										"[ -w " + file + " ] && echo \"Writable\" || echo \"Not Writable\"")),
								"Writable")) {
							//
							info(logger, format, StringUtils.rightPad("backup", length),
									StringUtils.trim(executeRemoteCommand(clientSession, String.join(String.join("",
											"echo ", file, ".`date -r ", file, " ", dateFormat, "`")))));
							//
							executeRemoteCommand(clientSession, String.join("", "cp -p ", file, " ", file, ".`date -r ",
									file, " ", dateFormat, "`"));
							//
						} else {
							//
							try (final ChannelExec channel = createExecChannel(clientSession,
									String.join("", "sudo cp -p ", file, " ", file, ".`date -r ", file, " ", dateFormat,
											"`"));
									final OutputStream out = new ByteArrayOutputStream();
									final OutputStream err = new ByteArrayOutputStream()) {
								//
								setOut(channel, out);
								//
								setErr(channel, err);
								//
								info(logger, format, StringUtils.rightPad("opened", length),
										isOpened(verify(open(channel), Duration.ofSeconds(5))));
								//
							} // try
								//
						} // if
							//
					} catch (final RemoteException e) {
						//
						error(logger, getMessage(e), e);
						//
					} // try
						//
					final X509Certificate x509Certificate = cast(X509Certificate.class, certificate);
					//
					final DateFormat df = new SimpleDateFormat("yyyyMMdd");
					//
					final String alias = StringUtils.joinWith("_",
							StringUtils.substringAfter(getName(getSubjectX500Principal(x509Certificate)), '='),
							format(df, getNotBefore(x509Certificate)), format(df, getNotAfter(x509Certificate)));
					//
					info(logger, format, StringUtils.rightPad("alias", length), alias);
					//
					final File filePem = new File(String.join(".", alias, "pem"));
					//
					info(logger, format, StringUtils.rightPad("filePem", length), getAbsolutePath(filePem));
					//
					testAndAccept(Objects::nonNull, getEncoded(certificate),
							x -> writeToPem(x, "CERTIFICATE", filePem));
					//
					setCertificateEntry(keyStore, alias, certificate);
					//
					try (final InputStream is2 = testAndApply(KeyStoreCertificateSshUpdater::exists, filePem,
							FileInputStream::new, null)) {
						//
						testAndAccept(Objects::nonNull, is2, x -> put(sftpClient, x, "/tmp/" + getName(filePem)));
						//
					} // try
						//
					final String keytool = Config.getKeytool(config);
					//
					info(logger, format, StringUtils.rightPad("keytool", length), keytool);
					//
					try (final ChannelExec channel = createExecChannel(clientSession,
							String.join("", "sudo ", keytool, " -import -keystore ", file, " -storepass ", storepass,
									" -file ", "/tmp/" + filePem.getName(), " -noprompt -alias ", alias));
							final OutputStream out = new ByteArrayOutputStream();
							final OutputStream err = new ByteArrayOutputStream()) {
						//
						setOut(channel, out);
						//
						setErr(channel, err);
						//
						info(logger, format, StringUtils.rightPad("opened", length),
								isOpened(verify(open(channel), Duration.ofSeconds(5))));
						//
					} // try
						//
					info(logger, "Certificate is added.");
					//
				} // if
					//
			} // try
				//
		} // try
			//
	}

	private static Boolean isOpened(final OpenFuture instance) {
		return instance != null ? Boolean.valueOf(instance.isOpened()) : null;
	}

	private static String getMessage(final Throwable instance) {
		return instance != null ? instance.getMessage() : null;
	}

	private static void setCertificateEntry(final KeyStore instance, final String alias, final Certificate cert)
			throws KeyStoreException {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "initialized")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null
				|| (Objects.equals(field.getType(), Boolean.TYPE) && Narcissus.getBooleanField(instance, field))) {
			//
			instance.setCertificateEntry(alias, cert);
			//
		} // if
			//
	}

	private static void load(final KeyStore instance, final InputStream stream, final char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(y -> size(y) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "keyStoreSpi")), Collectors.toList()),
				y -> get(y, 0), null);
		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.load(stream, password);
			//
		} // if
			//
	}

	private static void error(final Logger instance, final String msg, final Throwable t) {
		if (instance != null) {
			instance.error(msg, t);
		}
	}

	private static void info(final Logger instance, final String format, final Object... arguments) {
		if (instance != null) {
			instance.info(format, arguments);
		}
	}

	private static <T> T verify(final VerifiableFuture<T> instance, final Duration timeout) throws IOException {
		return instance != null ? instance.verify(timeout) : null;
	}

	private static OpenFuture open(final ClientChannel instance) throws IOException {
		return instance != null ? instance.open() : null;
	}

	private static void setErr(final ClientChannel instance, final OutputStream err) {
		if (instance != null) {
			instance.setErr(err);
		}
	}

	private static void setOut(final ClientChannel instance, final OutputStream out) {
		if (instance != null) {
			instance.setOut(out);
		}
	}

	private static boolean contains(final KeyStore instance, final byte[] encoded)
			throws CertificateEncodingException, KeyStoreException {
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "initialized")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		final Enumeration<String> aliases = instance != null && (field == null
				|| (Objects.equals(field.getType(), Boolean.TYPE) && Narcissus.getBooleanField(instance, field)))
						? instance.aliases()
						: null;
		//
		while (hasMoreElements(aliases)) {
			//
			if (Arrays.equals(getEncoded(instance.getCertificate(nextElement(aliases))), encoded)) {
				//
				return true;
				//
			} // if
				//
		} // while
			//
		return false;
		//
	}

	private static String addCharacter(final String instance, final int count, final char c) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(y -> size(y) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				y -> get(y, 0), null);
		//
		if (field != null && Narcissus.getField(instance, field) == null) {
			//
			return null;
			//
		} // if
			//
		StringBuilder sb = null;
		//
		final int length = StringUtils.length(instance);
		//
		for (int i = 0; instance != null && i < length; i++) {
			//
			if ((sb = ObjectUtils.getIfNull(sb, StringBuilder::new)) != null) {
				//
				sb.append(instance.charAt(i));
				//
			} // if
				//
			if (i % count == 1 && i < length - 1 && sb != null) {
				//
				sb.append(c);
				//
			} // if
				//
		} // for
			//
		return Objects.toString(sb);
		//
	}

	private static String getHost(final HostAndPort instance) {
		return instance != null ? instance.getHost() : null;
	}

	private static <E> E nextElement(final Enumeration<E> instance) {
		return instance != null ? instance.nextElement() : null;
	}

	private static boolean hasMoreElements(final Enumeration<?> instance) {
		return instance != null && instance.hasMoreElements();
	}

	private static String getPassword(final PasswordHolder instance) {
		return instance != null ? instance.getPassword() : null;
	}

	private static String getUsername(final UsernameHolder instance) {
		return instance != null ? instance.getUsername() : null;
	}

	private static void put(final SftpClient instnace, final InputStream stream, final String path) throws IOException {
		if (instnace != null) {
			instnace.put(stream, path);
		}
	}

	private static void addPublicKeyIdentity(final ClientAuthenticationManager instance, final KeyPair keyPair) {
		if (instance != null) {
			instance.addPublicKeyIdentity(keyPair);
		}
	}

	private static Collection<KeyPair> loadKeyPairs(final KeyPairResourceLoader instance, final SessionContext session,
			final Path path, final FilePasswordProvider passwordProvider, final OpenOption... options)
			throws IOException, GeneralSecurityException {
		return instance != null ? instance.loadKeyPairs(session, path, passwordProvider, options) : null;
	}

	private static boolean canWrite(final File instance) {
		return instance != null && instance.getPath() != null && instance.canWrite();
	}

	private static boolean exists(final File instance) {
		return instance != null && instance.getPath() != null && instance.exists();
	}

	private static boolean isFile(final File instance) {
		return instance != null && instance.getPath() != null && instance.isFile();
	}

	private static Path toPath(final File instance) {
		return instance != null && instance.getPath() != null ? instance.toPath() : null;
	}

	private static String toUpperCase(final String instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(y -> size(y) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				y -> get(y, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.toUpperCase() : null;
		//
	}

	private static void writeToPem(final byte[] encodedBytes, final String label, final File file) throws IOException {
		//
		final Base64.Encoder mimeEncoder = Base64.getMimeEncoder(64, new byte[] { '\n' });
		//
		final String base64Body = encodedBytes != null ? mimeEncoder.encodeToString(encodedBytes) : null;
		//
		try (final Writer writer = testAndApply(x -> x != null && x.getPath() != null, file, FileWriter::new, null)) {
			//
			if (writer != null) {
				//
				writer.write("-----BEGIN " + label + "-----\n");
				//
				if (base64Body != null) {
					//
					writer.write(base64Body);
					//
				} // if
					//
				writer.write("\n-----END " + label + "-----\n");
				//
			} // if
				//
		} // try
			//
	}

	private static String executeRemoteCommand(final ClientSession instance, final String command) throws IOException {
		return instance != null ? instance.executeRemoteCommand(command) : null;
	}

	private static ChannelExec createExecChannel(final ClientSession instance, final String command)
			throws IOException {
		return instance != null ? instance.createExecChannel(command) : null;
	}

	private static String format(final DateFormat instance, final Date date) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "calendar")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field != null && Narcissus.getField(instance, field) == null) {
			//
			return null;
			//
		} // if
			//
		if (instance instanceof SimpleDateFormat) {
			//
			return date != null ? instance.format(date) : null;
			//
		} // if
			//
		return instance.format(date);
		//
	}

	private static Date getNotBefore(final X509Certificate instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "info")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getNotBefore() : null;
		//
	}

	private static Date getNotAfter(final X509Certificate instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "info")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getNotAfter() : null;
		//
	}

	private static String nextAlphabetic(final RandomStringUtils instance, final int count) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "random")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.nextAlphabetic(count) : null;
		//
	}

	private static String getAlgorithm(final MessageDigest instance) {
		return instance != null ? instance.getAlgorithm() : null;
	}

	private static byte[] digest(final MessageDigest instance, final byte[] input) {
		//
		if (instance == null || input == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "digestSpi")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.digest(input) : null;
		//
	}

	private static byte[] getEncoded(final Certificate instance) throws CertificateEncodingException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "signedCert")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getEncoded() : null;
		//
	}

	private static Certificate getCertfiicate(final String url) throws IOException {
		//
		final HttpsURLConnection httpsURLConnection = cast(HttpsURLConnection.class, openConnection(testAndApply(x -> {
			//
			if (x == null) {
				//
				return false;
				//
			} // if
				//
			final Field field = testAndApply(y -> size(y) == 1,
					collect(filter(
							stream(testAndApply(Objects::nonNull, getClass(x), FieldUtils::getAllFieldsList, null)),
							f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
					y -> get(y, 0), null);
			//
			return field == null || Narcissus.getField(x, field) != null;
			//
		}, url, URL::new, null)));
		//
		connect(httpsURLConnection);
		//
		final List<Certificate> list = collect(
				filter(testAndApply(Objects::nonNull, getServerCertificates(httpsURLConnection), Arrays::stream, null),
						x -> isValid(DomainValidator.getInstance(),
								longestCommonSubstring(url,
										getName(getSubjectX500Principal(cast(X509Certificate.class, x)))))),
				Collectors.toList());
		//
		List<Certificate> result = null;
		//
		for (int i = 0; i < size(list); i++) {
			//
			add(result = ObjectUtils.getIfNull(result, ArrayList::new), get(list, i));
			//
		} // for
			//
		disconnect(httpsURLConnection);
		//
		if (size(result) > 1) {
			//
			throw new IllegalStateException();
			//
		} // if
			//
		return testAndApply(x -> size(x) == 1, result, x -> get(x, 0), null);
		//
	}

	private static boolean isValid(final DomainValidator instance, final String domain) {
		//
		if (instance == null) {
			//
			return false;
			//
		} // if
			//
		Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "domainRegex")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field != null && Narcissus.getField(instance, field) == null) {
			//
			return false;
			//
		} // if
			//
		if ((field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(domain), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null)) != null && Narcissus.getField(domain, field) == null) {
			//
			return false;
			//
		} // if
			//
		return domain != null && instance.isValid(domain);
		//
	}

	private static <E> void add(final Collection<E> instance, final E item) {
		if (instance != null) {
			instance.add(item);
		}
	}

	private static String longestCommonSubstring(final String a, final String b) {
		//
		int start = 0, max = 0;
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(stream(testAndApply(Objects::nonNull, getClass(a), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		final boolean conditionA = or(field, Objects::isNull, f -> Narcissus.getField(a, f) != null);
		//
		final boolean conditionB = or(field, Objects::isNull,
				f -> and(b, Objects::nonNull, g -> Narcissus.getField(g, f) != null));
		//
		for (int i = 0; and(conditionA, (value, index) -> index < StringUtils.length(value), a, i); i++) {
			//
			for (int j = 0; and(conditionB, (value, index) -> index < StringUtils.length(value), b, j); j++) {
				//
				int x = 0;
				//
				while (a.charAt(i + x) == b.charAt(j + x)) {
					//
					x++;
					//
					if (((i + x) >= a.length()) || ((j + x) >= b.length())) {
						//
						break;
						//
					} // if
						//
				} // while
					//
				if (x > max) {
					//
					max = x;
					//
					start = i;
					//
				} // if
					//
			} // for
				//
		} // for
			//
		return conditionA ? StringUtils.substring(a, start, start + max) : null;
		//
	}

	private static <T> boolean and(final boolean condition, final ObjIntPredicate<T> objIntPredicate, final T value,
			final int integer) {
		return condition && objIntPredicate != null && objIntPredicate.test(value, integer);
	}

	private static <T> boolean and(final T value, final Predicate<T> a, final Predicate<T> b) {
		return test(a, value) && test(b, value);
	}

	private static <T> boolean or(final T value, final Predicate<T> a, final Predicate<T> b) {
		return test(a, value) || test(b, value);
	}

	private static String getName(final X500Principal instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "thisX500Name")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getName() : null;
		//
	}

	private static X500Principal getSubjectX500Principal(final X509Certificate instance) {
		return instance != null ? instance.getSubjectX500Principal() : null;
	}

	private static URLConnection openConnection(final URL instance) throws IOException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "handler")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.openConnection() : null;
		//
	}

	private static <T> T cast(final Class<T> clz, final Object instance) {
		return clz != null && clz.isInstance(instance) ? clz.cast(instance) : null;
	}

	private static void connect(final HttpsURLConnection instance) throws IOException {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), DELEGATE)), Collectors.toList()),
				x -> get(x, 0), null);

		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.connect();
			//
		} // if
			//
	}

	private static void disconnect(final HttpsURLConnection instance) {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), DELEGATE)), Collectors.toList()),
				x -> get(x, 0), null);

		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.disconnect();
			//
		} // if
			//
	}

	private static Certificate[] getServerCertificates(final HttpsURLConnection instance)
			throws SSLPeerUnverifiedException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), DELEGATE)), Collectors.toList()),
				x -> get(x, 0), null);

		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getServerCertificates() : null;
		//
	}

	private static char[] toCharArray(final String instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(y -> size(y) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				y -> get(y, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.toCharArray() : null;
		//
	}

	private static InputStream read(final SftpClient instnace, final String path) throws IOException {
		return instnace != null && path != null ? instnace.read(path) : null;
	}

	private static <T, U, E extends Exception> void testAndAccept(final BiPredicate<T, U> predicate, final T t,
			final U u, final FailableBiConsumer<T, U, E> consumer) throws E {
		if (predicate != null && predicate.test(t, u) && consumer != null) {
			consumer.accept(t, u);
		}
	}

	private static <T, E extends Exception> void testAndAccept(final Predicate<T> predicate, final T value,
			final FailableConsumer<T, E> consumer) throws E {
		if (test(predicate, value)) {
			accept(consumer, value);
		}
	}

	private static <T, E extends Exception> void accept(final FailableConsumer<T, E> instance, final T value) throws E {
		if (instance != null) {
			instance.accept(value);
		}
	}

	private static void addPasswordIdentity(final ClientAuthenticationManager instance, final String password) {
		if (instance != null) {
			instance.addPasswordIdentity(password);
		}
	}

	private static boolean isSuccess(final AuthFuture instance) {
		return instance != null && instance.isSuccess();
	}

	private static AuthFuture auth(final ClientSession instance) throws IOException {
		return instance != null ? instance.auth() : null;
	}

	private static SftpClient createSftpClient(final SftpClientFactory instnace, final ClientSession session)
			throws IOException {
		return instnace != null ? instnace.createSftpClient(session) : null;
	}

	private static <S extends Session> S getSession(final SessionHolder<S> instance) {
		return instance != null ? instance.getSession() : null;
	}

	private static <T> T verify(final VerifiableFuture<T> instnace) throws IOException {
		return instnace != null ? instnace.verify() : null;
	}

	private static ConnectFuture connect(final ClientSessionCreator instance, final String username, final String host,
			final int port) throws IOException {
		return instance != null ? instance.connect(username, host, port) : null;
	}

	private static <T, U, R, E extends Exception> R testAndApply(final BiPredicate<T, U> predicate, final T t,
			final U u, final FailableBiFunction<T, U, R, E> functionTrue,
			final FailableBiFunction<T, U, R, E> functionFalse) throws E {
		return predicate != null && predicate.test(t, u) ? apply(functionTrue, t, u) : apply(functionFalse, t, u);
	}

	private static <T, U, R, E extends Exception> R apply(final FailableBiFunction<T, U, R, E> instance, final T t,
			final U u) throws E {
		return instance != null ? instance.apply(t, u) : null;
	}

	private static <V> V get(final Map<?, V> instance, final Object key) {
		return instance != null ? instance.get(key) : null;
	}

	private static void start(final SshClient instance) {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "state")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || (Narcissus.getField(instance, field)) != null) {
			//
			instance.start();
			//
		} // if
			//
	}

	private static Map<String, String> toMap(final String... ss) {
		//
		Map<String, String> map = null;
		//
		Entry<String, String> entry = null;
		//
		for (int i = 0; i < length(ss); i++) {
			//
			if ((entry = toEntry(ArrayUtils.get(ss, i))) == null) {
				//
				continue;
				//
			} // if
				//
			put(map = ObjectUtils.getIfNull(map, LinkedHashMap::new), getKey(entry), getValue(entry));
			//
		} // for
			//
		return map;
		//
	}

	private static <K, V> void put(final Map<K, V> instance, final K key, final V value) {
		if (instance != null) {
			instance.put(key, value);
		}
	}

	private static <K> K getKey(final Entry<K, ?> instance) {
		return instance != null ? instance.getKey() : null;
	}

	private static <V> V getValue(final Entry<?, V> instance) {
		return instance != null ? instance.getValue() : null;
	}

	private static Entry<String, String> toEntry(final String string) {
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(string), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (string != null && field != null && Narcissus.getField(string, field) == null) {
			//
			return null;
			//
		} // if
			//
		if (Objects.equals(string, "=")) {
			//
			return Pair.of("", "");
			//
		} else if (string != null && string.length() == 2 && string.charAt(0) == '=') {
			//
			return Pair.of("", string.substring(1, string.length()));
			//
		} else if (string != null && string.length() == 2 && string.charAt(string.length() - 1) == '=') {
			//
			return Pair.of(string.substring(0, string.length() - 1), "");
			//
		} else if (string != null && string.indexOf('=') >= 0 && string.indexOf('=') == string.lastIndexOf('=')) {
			//
			return Pair.of(StringUtils.substringBefore(string, '='), StringUtils.substringAfter(string, '='));
			//
		} else if (string != null && string.length() > 2 && string.indexOf('=') != string.lastIndexOf('=')) {
			//
			return Pair.of(StringUtils.substring(string, 0, string.indexOf('=')),
					StringUtils.substring(string, string.indexOf('=') + 1));
			//
		} // if
			//
		return null;
		//
	}

	private static <E> E get(final List<E> instance, final int index) {
		return instance != null ? instance.get(index) : null;
	}

	private static int size(final Collection<?> instance) {
		return instance != null ? instance.size() : 0;
	}

	private static String getName(final Member instance) {
		return instance != null ? instance.getName() : null;
	}

	private static String getName(final File instance) {
		return instance != null && instance.getPath() != null ? instance.getName() : null;
	}

	private static String getAbsolutePath(final File instance) {
		return instance != null && instance.getPath() != null ? instance.getAbsolutePath() : null;
	}

	private static <T, R, A> R collect(final Stream<T> instance, final Collector<? super T, A, R> collector) {
		//
		return instance != null && (collector != null || Proxy.isProxyClass(getClass(instance)))
				? instance.collect(collector)
				: null;
		//
	}

	private static <T> Stream<T> filter(final Stream<T> instance, final Predicate<? super T> predicate) {
		return instance != null ? instance.filter(predicate) : instance;
	}

	private static <T> Stream<T> stream(final Collection<T> instance) {
		return instance != null ? instance.stream() : null;
	}

	private static <T, R, E extends Throwable> R testAndApply(final Predicate<T> predicate, final T value,
			final FailableFunction<T, R, E> functionTrue, final FailableFunction<T, R, E> functionFalse) throws E {
		return test(predicate, value) ? apply(functionTrue, value) : apply(functionFalse, value);
	}

	private static <T, R, E extends Throwable> R apply(final FailableFunction<T, R, E> instance, final T value)
			throws E {
		return instance != null ? instance.apply(value) : null;
	}

	private static <T> boolean test(final Predicate<T> instance, final T value) {
		return instance != null && instance.test(value);
	}

	private static Class<?> getClass(final Object instance) {
		return instance != null ? instance.getClass() : null;
	}

	private static int length(final Object[] instance) {
		return instance != null ? instance.length : 0;
	}

}