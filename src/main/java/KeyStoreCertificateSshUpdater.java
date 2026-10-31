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
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.rmi.RemoteException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
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

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.function.FailableBiFunction;
import org.apache.commons.lang3.function.FailableConsumer;
import org.apache.commons.lang3.function.FailableFunction;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.sshd.client.ClientAuthenticationManager;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionCreator;
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

import io.github.toolfactory.narcissus.Narcissus;

public class KeyStoreCertificateSshUpdater {

	public static void main(final String[] args) throws Exception {
		//
		final Map<String, String> map = toMap(args);
		//
		final File tempFile = File.createTempFile(nextAlphabetic(RandomStringUtils.secure(), 3), null);
		//
		if (tempFile != null) {
			//
			tempFile.deleteOnExit();
			//
		} // if
			//
		try (final SshClient sshClient = SshClient.setUpDefaultClient()) {
			//
			start(sshClient);
			//
			final MessageDigest md = MessageDigest.getInstance("SHA-1");
			//
			final String algorithm = getAlgorithm(md);
			//
			final int length = Math.max(StringUtils.length(algorithm), 9);
			//
			final String host = get(map, "host");
			//
			System.out.println(StringUtils.rightPad("host", length) + "=" + host);
			//
			final int port = NumberUtils.toInt(get(map, "port"), 22);
			//
			System.out.println(StringUtils.rightPad("port", length) + "=" + port);
			//
			final String user = get(map, "user");
			//
			System.out.println(StringUtils.rightPad("user", length) + "=" + user);
			//
			final String file = get(map, "file");
			//
			System.out.println(StringUtils.rightPad("file", length) + "=" + file);
			//
			final String url = get(map, "url");
			//
			System.out.println(StringUtils.rightPad("url", length) + "=" + url);
			//
			System.out.println(StringUtils.rightPad("tempFile", length) + "="
					+ (tempFile != null ? tempFile.getAbsolutePath() : null));
			//
			try (final ClientSession clientSession = testAndApply(
					(a, b) -> Boolean.logicalAnd(a != null, StringUtils.isNotEmpty(b)), user, host,
					(a, b) -> getSession(verify(connect(sshClient, a, b, port))), null)) {
				//
				testAndAccept(Objects::nonNull, get(map, "password"), x -> addPasswordIdentity(clientSession, x));
				//
				final String publicKeyFile = get(map, "publicKey");
				//
				System.out.println(StringUtils.rightPad("publicKey", length) + "=" + publicKeyFile);
				//
				testAndAccept(Objects::nonNull,
						testAndApply(x -> size(x) == 1,
								testAndApply(x -> Boolean.logicalAnd(exists(x), isFile(x)),
										testAndApply(Objects::nonNull, publicKeyFile, File::new, null),
										x -> loadKeyPairs(PuttyKeyUtils.DEFAULT_INSTANCE, null, toPath(x), null), null),
								x -> new ArrayList<>(x).get(0), null),
						x -> addPublicKeyIdentity(clientSession, x));
				//
				try (final SftpClient sftpClient = isSuccess(verify(auth(clientSession)))
						? createSftpClient(SftpClientFactory.instance(), clientSession)
						: null; final InputStream is = read(sftpClient, file)) {
					//
					if (is != null && tempFile != null && tempFile.exists() && tempFile.canWrite()) {
						//
						FileUtils.writeByteArrayToFile(tempFile, IOUtils.toByteArray(is));
						//
					} // is
						//
					final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
					//
					final String storepass = get(map, "storepass");
					//
					if (keyStore != null) {
						//
						try (final InputStream is2 = testAndApply(
								x -> x != null && x.exists() && x.isFile() && x.length() > 0, tempFile,
								FileInputStream::new, null)) {
							//
							keyStore.load(is2, toCharArray(storepass));
							//
						} // try
							//
						final Certificate certificate = getCertfiicate(url);
						//
						final byte[] encoded = getEncoded(certificate);
						//
						String hexString = testAndApply(Objects::nonNull, digest(md, encoded), Hex::encodeHexString,
								null);
						//
						final StringBuilder sb = new StringBuilder();
						//
						for (int i = 0; hexString != null && i < hexString.length(); i++) {
							//
							sb.append(hexString.charAt(i));
							//
							if (i % 2 == 1 && i < hexString.length() - 1) {
								//
								sb.append(':');
								//
							} // if
								//
						} // for
							//
						System.out.println(StringUtils.rightPad(algorithm, length) + "="
								+ (hexString = toUpperCase(Objects.toString(sb))));
						//
						final Enumeration<String> aliases = keyStore.aliases();
						//
						boolean found = false;
						//
						while (aliases != null && aliases.hasMoreElements()) {
							//
							if ((found = Arrays.equals(getEncoded(keyStore.getCertificate(aliases.nextElement())),
									encoded))) {
								//
								break;
								//
							} // if
								//
						} // while
							//
						if (found) {
							//
							System.out.println("Certificate is found.");
							//
						} else {
							//
							try {
								//
								if (Objects.equals(
										StringUtils.trim(executeRemoteCommand(clientSession,
												"[ -w " + file + " ] && echo \"Writable\" || echo \"Not Writable\"")),
										"Writable")) {
									//
									System.out.println(StringUtils.rightPad("backup", length) + "="
											+ StringUtils.trim(
													executeRemoteCommand(clientSession, String.join(String.join("",
															"echo ", file, ".`date -r ", file, " +%Y%m%d_%H%M%S`")))));
									//
									executeRemoteCommand(clientSession, String.join("", "cp -p ", file, " ", file,
											".`date -r ", file, " +%Y%m%d_%H%M%S`"));
									//
								} else {
									//
									try (final ChannelExec channel = createExecChannel(clientSession,
											String.join("", "sudo cp -p ", file, " ", file, ".`date -r ", file,
													" +%Y%m%d_%H%M%S`"));
											final OutputStream out = new ByteArrayOutputStream();
											final OutputStream err = new ByteArrayOutputStream()) {
										//
										if (channel != null) {
											//
											channel.setOut(out);
											//
											channel.setErr(err);
											//
											final OpenFuture openFuture = channel.open().verify(Duration.ofSeconds(5));
											//
											System.out.println(StringUtils.rightPad("opened", length) + "="
													+ (openFuture != null ? openFuture.isOpened() : null));
											//
										} // if
											//
									} // try
										//
								} // if
									//
							} catch (final RemoteException e) {
								//
								e.printStackTrace();
								//
							} // try
								//
							final X509Certificate x509Certificate = cast(X509Certificate.class, certificate);
							//
							final DateFormat df = new SimpleDateFormat("yyyyMMdd");
							//
							final String alias = StringUtils.joinWith("_",
									StringUtils.substringAfter(getName(getSubjectX500Principal(x509Certificate)), '='),
									format(df, getNotBefore(x509Certificate)),
									format(df, getNotAfter(x509Certificate)));
							//
							System.out.println(StringUtils.rightPad("alias", length) + "=" + alias);
							//
							final File filePem = new File(String.join(".", alias, "pem"));
							//
							System.out.println(StringUtils.rightPad("filePem", length) + "="
									+ (filePem != null ? filePem.getAbsolutePath() : null));
							//
							writeToPem(getEncoded(certificate), "CERTIFICATE", filePem);
							//
							keyStore.setCertificateEntry(alias, certificate);
							//
							try (final InputStream is2 = testAndApply(Objects::nonNull, filePem, FileInputStream::new,
									null)) {
								//
								sftpClient.put(is2, "/tmp/" + filePem.getName());
								//
							} // try
								//
							final String keytool = get(map, "keytool");
							//
							System.out.println(StringUtils.rightPad("keytool", length) + "=" + keytool);
							//
							try (final ChannelExec channel = createExecChannel(clientSession,
									String.join("", "sudo ", keytool, " -import -keystore ", file, " -storepass ",
											storepass, " -file ", "/tmp/" + filePem.getName(), " -noprompt -alias ",
											alias));
									final OutputStream out = new ByteArrayOutputStream();
									final OutputStream err = new ByteArrayOutputStream()) {
								//
								if (channel != null) {
									//
									channel.setOut(out);
									//
									channel.setErr(err);
									//
									final OpenFuture openFuture = channel.open().verify(Duration.ofSeconds(5));
									//
									System.out.println(StringUtils.rightPad("opened", length) + "="
											+ (openFuture != null ? openFuture.isOpened() : null));
									//
								} // if
									//
							} // try
								//
							System.err.println("Certificate is added.");
							//
						} // if
							//
					} // if
						//
				} // try
					//
			} // try
				//
		} // try
			//
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
		return instance != null ? instance.toUpperCase() : null;
	}

	private static void writeToPem(byte[] encodedBytes, String label, final File file) throws IOException {
		//
		final Base64.Encoder mimeEncoder = Base64.getMimeEncoder(64, new byte[] { '\n' });
		//
		final String base64Body = encodedBytes != null ? mimeEncoder.encodeToString(encodedBytes) : null;
		//
		try (final Writer writer = testAndApply(Objects::nonNull, file, FileWriter::new, null)) {
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
		if (instance instanceof SimpleDateFormat) {
			//
			return date != null ? instance.format(date) : null;
			//
		} // if
			//
		return instance != null ? instance.format(date) : null;
		//
	}

	private static Date getNotBefore(final X509Certificate instnace) {
		return instnace != null ? instnace.getNotBefore() : null;
	}

	private static Date getNotAfter(final X509Certificate instnace) {
		return instnace != null ? instnace.getNotAfter() : null;
	}

	private static String nextAlphabetic(final RandomStringUtils instance, final int count) {
		return instance != null ? instance.nextAlphabetic(count) : null;
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
						f -> Objects.equals(getName(f), "digestBuffer")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.digest(input) : null;
		//
	}

	private static byte[] getEncoded(final Certificate instance) throws CertificateEncodingException {
		return instance != null ? instance.getEncoded() : null;
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
							f -> Objects.equals(getName(f), "value")), Collectors.toList()),
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
						f -> Objects.equals(getName(f), "value")), Collectors.toList()),
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
						f -> Objects.equals(getName(f), "value")), Collectors.toList()),
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
						f -> Objects.equals(getName(f), "delegate")), Collectors.toList()),
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
						f -> Objects.equals(getName(f), "delegate")), Collectors.toList()),
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
						f -> Objects.equals(getName(f), "delegate")), Collectors.toList()),
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
						f -> Objects.equals(getName(f), "value")), Collectors.toList()),
				y -> get(y, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.toCharArray() : null;
		//
	}

	private static InputStream read(final SftpClient instnace, final String path) throws IOException {
		return instnace != null && path != null ? instnace.read(path) : null;
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
						f -> Objects.equals(getName(f), "value")), Collectors.toList()),
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