package org.apache.sshd.client;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.lang.annotation.Annotation;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.FileSystems;
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
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.EventObject;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Properties;
import java.util.function.BiConsumer;
import java.util.function.BiPredicate;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.ToIntFunction;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;
import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.ListCellRenderer;
import javax.swing.MutableComboBoxModel;
import javax.swing.WindowConstants;
import javax.swing.border.Border;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.JTextComponent;
import javax.swing.text.PlainDocument;
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
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.apache.commons.lang3.function.FailableBiConsumer;
import org.apache.commons.lang3.function.FailableBiFunction;
import org.apache.commons.lang3.function.FailableConsumer;
import org.apache.commons.lang3.function.FailableFunction;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.UrlValidator;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionCreator;
import org.apache.sshd.common.SshConstants;
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
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.google.common.net.HostAndPort;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Crypt32Util;
import com.sun.jna.platform.win32.Kernel32Util;
import com.sun.jna.platform.win32.KnownFolders;
import com.sun.jna.platform.win32.Ole32;
import com.sun.jna.platform.win32.Shell32;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import io.github.toolfactory.narcissus.Narcissus;
import net.miginfocom.swing.MigLayout;

public class KeyStoreCertificateSshUpdater extends JPanel implements ActionListener, DocumentListener {

	private static final long serialVersionUID = -7414566256715350073L;

	private static final Logger LOG = LoggerFactory.getLogger(KeyStoreCertificateSshUpdater.class);

	private static final String DELEGATE = "delegate";

	private static final String VALUE = "value";

	private static final String PASSWORD = "password";

	private static final String KEYTOOL = "keytool";

	private static final String SHA1 = "SHA-1";

	private static final String OBJECT_LOCK = "objectLock";

	@Target(ElementType.FIELD)
	@Retention(RetentionPolicy.RUNTIME)
	private @interface Note {
		String value();
	}

	@Note("Host")
	private JTextComponent tfHost = null;

	@Note("Port")
	private JTextComponent tfPort = null;

	@Note("Username")
	private JTextComponent tfUsername = null;

	@Target(ElementType.FIELD)
	@Retention(RetentionPolicy.RUNTIME)
	private @interface Password {
	}

	@Password
	private JTextComponent tfPassword = null;

	@Note("Public Key")
	private JTextComponent tfPublicKey = null;

	@Note("Key Tool")
	private JTextComponent tfKeyTool = null;

	@Note("Key Store Path")
	private JTextComponent tfKeyStorePath = null;

	@Password
	private JTextComponent tfKeyStorePassword = null;

	private JTextComponent tfUrl = null;

	@Note("Public Key")
	private AbstractButton btnPublicKey = null;

	private AbstractButton btnExecute = null;

	private Map<String, String> map = null;

	private JComboBox<FileZillaProfile> jcb = null;

	private static class FileZillaProfile {

		private HostAndPort hostAndPort = null;

		private BasicCredentialsProvider basicCredentialsProvider = null;

		private String name = null;

		private File keyFile = null;

		private HostAndPort getHostAndPort() {
			return hostAndPort;
		}

		private static HostAndPort getHostAndPort(final FileZillaProfile instance) {
			return instance != null ? instance.getHostAndPort() : null;
		}

	}

	public static void main(final String[] args) throws Exception {
		//
		final File tempFile = createTempFile(nextAlphabetic(RandomStringUtils.secure(), 3), null);
		//
		deleteOnExit(tempFile);
		//
		final Map<String, String> map = toMap(args);
		//
		if (Boolean.logicalOr(isGui(), Objects.equals(get(map, "gui"), "true"))) {
			//
			final KeyStoreCertificateSshUpdater instance = new KeyStoreCertificateSshUpdater();
			//
			instance.setLayout(new MigLayout());
			//
			instance.add(new JLabel("FileZilla profile"));
			//
			final List<FileZillaProfile> fileZillaProfiles = getFileZillaProfiles(ObjectUtils.getIfNull(
					getFileZillaSiteManagerXmlFile(
							testAndApply(Objects::nonNull, getRoamingAppDataFolder(), File::new, null)),
					() -> new File("sitemanager.xml")));
			//
			DefaultComboBoxModel<FileZillaProfile> cbm = null;
			//
			for (int i = 0; i < size(fileZillaProfiles); i++) {
				//
				addElement(cbm = ObjectUtils.getIfNull(cbm, DefaultComboBoxModel::new), get(fileZillaProfiles, i));
				//
			} // for
				//
			instance.jcb = testAndApply(Objects::nonNull, cbm, JComboBox::new, x -> new JComboBox<>());
			//
			final ListCellRenderer<?> lcr = getRenderer(instance.jcb);
			//
			setRenderer(instance.jcb, (list, value, index, isSelected, cellHasFocus) -> {
				//
				final Component component = getListCellRendererComponent(((ListCellRenderer) lcr), list, value, index,
						isSelected, cellHasFocus);
				//
				final StringBuilder sb = new StringBuilder(
						StringUtils.defaultString(value != null ? value.name : null));
				//
				testAndAccept(StringUtils::isNotEmpty, sb, x -> append(x, ' '));
				//
				setText(cast(JLabel.class, component),
						Objects.toString(sb.append(FileZillaProfile.getHostAndPort(value))));
				//
				return component;
				//
			});
			//
			addActionListener(instance.jcb, instance);
			//
			final String wrap = "wrap";
			//
			instance.add(instance.jcb, wrap);
			//
			instance.add(new JLabel("Host"));
			//
			instance.add(instance.tfHost = new JTextField(), String.format("wmin %1$s,%2$s", 200, wrap));
			//
			instance.add(new JLabel("Port"));
			//
			final String growx = "growx";
			//
			final String format = "%1$s,%2$s";
			//
			instance.add(instance.tfPort = new JTextField(), String.format(format, growx, wrap));
			//
			setDocument(instance.tfPort, createDocument(instance.tfPort, Collections.max(getPorts())));
			//
			addKeyListener(instance.tfPort, createKeyListener());
			//
			instance.add(new JLabel("User"));
			//
			instance.add(instance.tfUsername = new JTextField(), String.format(format, growx, wrap));
			//
			instance.add(new JLabel("Password"));
			//
			instance.add(instance.tfPassword = new JPasswordField(), String.format(format, growx, wrap));
			//
			instance.add(new JLabel("Public Key"));
			//
			instance.add(instance.tfPublicKey = new JTextField(), growx);
			//
			instance.tfPublicKey.setEditable(false);
			//
			instance.add(instance.btnPublicKey = new JButton("Select"), wrap);
			//
			instance.add(new JLabel("Key Tool"));
			//
			instance.add(instance.tfKeyTool = new JTextField(), String.format(format, growx, wrap));
			//
			instance.add(new JLabel("Key Store Path"));
			//
			instance.add(instance.tfKeyStorePath = new JTextField(), String.format(format, growx, wrap));
			//
			instance.add(new JLabel("Key Store Password"));
			//
			instance.add(instance.tfKeyStorePassword = new JPasswordField(), String.format(format, growx, wrap));
			//
			instance.add(new JLabel("URL"));
			//
			instance.add(instance.tfUrl = new JTextField(), String.format(format, growx, wrap));
			//
			addDocumentListener(getDocument(instance.tfUrl), createDocumentListener(instance.tfUrl,
					getBorder(instance.tfUrl), BorderFactory.createLineBorder(Color.RED, 2)));
			//
			instance.add(new JLabel());
			//
			instance.add(instance.btnExecute = new JButton("Execute"), wrap);
			//
			final Supplier<Stream<Field>> supplier = () -> testAndApply(Objects::nonNull,
					getDeclaredFields(KeyStoreCertificateSshUpdater.class), Arrays::stream, null);
			//
			forEach(map(filter(get(supplier), f -> isAssignableFrom(AbstractButton.class, getType(f))),
					f -> cast(AbstractButton.class, testAndApply(KeyStoreCertificateSshUpdater::isStatic, f,
							Narcissus::getStaticField, x -> Narcissus.getField(instance, x)))),
					x -> addActionListener(x, instance));
			//
			final Properties properties = new Properties();
			//
			try (final InputStream is = testAndApply(
					x -> and(x, KeyStoreCertificateSshUpdater::exists, KeyStoreCertificateSshUpdater::isFile),
					new File("KeyStoreCertificateSshUpdater.properties"), FileInputStream::new, null)) {
				//
				testAndAccept(Objects::nonNull, is, properties::load);
				//
			} // try
				//
			setText(instance, properties);
			//
			HostAndPort hostAndPort = null;
			//
			final String host = getText(instance.tfHost);
			//
			final String port = getText(instance.tfPort);
			//
			if (NumberUtils.isDigits(port)) {
				//
				hostAndPort = fromParts(host, NumberUtils.toInt(port, SshConstants.DEFAULT_PORT));
				//
			} else {
				//
				hostAndPort = HostAndPort.fromHost(host);
				//
			} // if
				//
			int[] ints = null;
			//
			for (int i = 0; cbm != null && i < cbm.getSize(); i++) {
				//
				if (Objects.equals(FileZillaProfile.getHostAndPort(cbm.getElementAt(i)), hostAndPort)) {
					//
					ints = ArrayUtils.add(ints, i);
					//
				} // if
					//
			} // for
				//
			if (ints != null && ints.length == 1 && cbm != null) {
				//
				cbm.setSelectedItem(cbm.getElementAt(ints[0]));
				//
			} // if
				//
			final KeyListener keyListener = createKeyListener2(instance);
			//
			forEach(map(filter(get(supplier), f -> isAssignableFrom(JTextComponent.class, getType(f))),
					f -> cast(JTextComponent.class, testAndApply(KeyStoreCertificateSshUpdater::isStatic, f,
							Narcissus::getStaticField, x -> Narcissus.getField(instance, x)))),
					x -> {
						//
						addDocumentListener(getDocument(x), instance);
						//
						addKeyListener(x, keyListener);
						//
					});
			//
			final JFrame jFrame = getAsBooleanAndGet(() -> !GraphicsEnvironment.isHeadless(), JFrame::new);
			//
			setDefaultCloseOperation(jFrame, WindowConstants.EXIT_ON_CLOSE);
			//
			add(jFrame, instance);
			//
			pack(jFrame);
			//
			setVisible(jFrame, true);
			//
			return;
			//
		} // if
			//
		try (final SshClient sshClient = SshClient.setUpDefaultClient()) {
			//
			start(sshClient);
			//
			if (containsKey(map, "config")) {
				//
				perform(sshClient, testAndApply(
						x -> and(x, KeyStoreCertificateSshUpdater::exists, KeyStoreCertificateSshUpdater::isFile),
						testAndApply(Objects::nonNull, get(map, "config"), File::new, null),
						x -> parse(newDocumentBuilder(DocumentBuilderFactory.newInstance()), x), null), get(map, "url"),
						tempFile);
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
				config.keytool = get(map, KEYTOOL);
				//
				config.keyStorePathPassword = Pair.of(get(map, "keystore"), get(map, "storepass"));
				//
				perform(sshClient, config, tempFile, get(map, "url"), getMessageDigest(SHA1), LOG);
				//
			} // if
				//
		} // try
			//
	}

	private static HostAndPort fromParts(final String host, final int port) {
		//
		final List<Method> ms = collect(
				filter(testAndApply(Objects::nonNull, HostAndPort.class.getDeclaredMethods(), Arrays::stream, null),
						x -> Boolean.logicalAnd(Objects.equals(getName(x), "fromParts"),
								Arrays.equals(getParameterTypes(x), new Class<?>[] { String.class, Integer.TYPE }))),
				Collectors.toList());
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(host), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return cast(HostAndPort.class,
				testAndApply(
						(a, b) -> Boolean.logicalAnd(isStatic(a),
								b != null && (field == null || Narcissus.getField(b, field) != null)),
						testAndApply(x -> size(x) == 1, ms, x -> get(x, 0), null), host,
						(a, b) -> Narcissus.invokeStaticMethod(a, b, port), null));
		//
	}

	private static List<FileZillaProfile> getFileZillaProfiles(final File file) throws Exception {
		//
		final XPath xp = newXPath(XPathFactory.newInstance());
		//
		final NodeList nodeList = cast(NodeList.class, evaluate(xp, "/*/*/Server",
				testAndApply(x -> and(x, KeyStoreCertificateSshUpdater::exists, KeyStoreCertificateSshUpdater::isFile),
						file, x -> parse(newDocumentBuilder(DocumentBuilderFactory.newInstance()), x), null),
				XPathConstants.NODESET));
		//
		Node node, node1, node2 = null;
		//
		Decoder decoder = null;
		//
		BasicCredentialsImpl bci = null;
		//
		FileZillaProfile zfp = null;
		//
		List<FileZillaProfile> list = null;
		//
		for (int i = 0; i < getLength(nodeList); i++) {
			//
			(zfp = new FileZillaProfile()).name = getTextContent(
					cast(Node.class, evaluate(xp, "Name", node = item(nodeList, i), XPathConstants.NODE)));
			//
			if (Boolean.logicalAnd((node1 = cast(Node.class, evaluate(xp, "Host", node, XPathConstants.NODE))) != null,
					(node2 = cast(Node.class, evaluate(xp, "Port", node, XPathConstants.NODE))) != null)) {
				//
				zfp.hostAndPort = fromParts(getTextContent(node1),
						NumberUtils.toInt(getTextContent(node2), SshConstants.DEFAULT_PORT));
				//
			} else if (node1 != null) {
				//
				zfp.hostAndPort = HostAndPort.fromHost(getTextContent(node1));
				//
			} else {
				//
				throw new RuntimeException();
				//
			} // if
				//
			if (Boolean.logicalAnd((node1 = cast(Node.class, evaluate(xp, "User", node, XPathConstants.NODE))) != null,
					(node2 = cast(Node.class, evaluate(xp, "Pass", node, XPathConstants.NODE))) != null)) {
				//
				if (Objects.equals(getNodeValue(getNamedItem(getAttributes(node2), "encoding")), "base64")) {
					//
					zfp.basicCredentialsProvider = new BasicCredentialsImpl(getTextContent(node1), testAndApply(
							Objects::nonNull,
							decode(decoder = ObjectUtils.getIfNull(decoder, Base64::getDecoder), getTextContent(node2)),
							String::new, null));
					//
				} else {
					//
					throw new RuntimeException();
					//
				} // if
					//
			} else if (node1 != null) {
				//
				(bci = new BasicCredentialsImpl()).setUsername(getTextContent(node1));
				//
				zfp.basicCredentialsProvider = bci;
				//
			} else {
				//
				throw new RuntimeException();
				//
			} // if
				//
			zfp.keyFile = testAndApply(Objects::nonNull,
					getTextContent(cast(Node.class, evaluate(xp, "Keyfile", node, XPathConstants.NODE))), File::new,
					null);
			//
			add(list = ObjectUtils.getIfNull(list, ArrayList::new), zfp);
			//
		} // for
			//
		return list;
		//
	}

	private static <E> void addElement(final MutableComboBoxModel<E> instance, final E item) {
		if (instance != null) {
			instance.addElement(item);
		}
	}

	private static StringBuilder append(final StringBuilder instance, final char c) {
		//
		if (instance == null) {
			//
			return instance;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.append(c) : instance;
		//
	}

	private static <E> Component getListCellRendererComponent(final ListCellRenderer<E> instance,
			final JList<? extends E> list, final E value, final int index, final boolean isSelected,
			final boolean cellHasFocus) {
		return instance != null ? instance.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
				: null;
	}

	private static <E> void addActionListener(final JComboBox<E> instance, final ActionListener actionListener) {
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
						f -> Objects.equals(getName(f), "listenerList")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.addActionListener(actionListener);
			//
		} // if
			//
	}

	private static <E> void setRenderer(final JComboBox<E> instance,
			final ListCellRenderer<? super E> listCellRenderer) {
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
						f -> Objects.equals(getName(f), OBJECT_LOCK)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.setRenderer(listCellRenderer);
			//
		} // if
			//
	}

	private static <E> ListCellRenderer<? super E> getRenderer(final JComboBox<E> instance) {
		return instance != null ? instance.getRenderer() : null;
	}

	private static String getTextContent(final Node instance) {
		return instance != null ? instance.getTextContent() : null;
	}

	private static String getRoamingAppDataFolder() {
		//
		if (isWindows()) {
			//
			final PointerByReference pbr = new PointerByReference();
			//
			try {
				//
				final Shell32 shell32 = Shell32.INSTANCE;
				//
				final HRESULT hrKnown = shell32 != null
						? shell32.SHGetKnownFolderPath(KnownFolders.FOLDERID_RoamingAppData, 0, (HANDLE) null, pbr)
						: null;

				if (hrKnown != null && hrKnown.intValue() == 0 && pbr.getValue() != null) {
					//
					return getWideString(pbr.getValue(), 0);
					//
				} // if
					//
			} finally {
				//
				final Ole32 ole32 = Ole32.INSTANCE;
				//
				if (ole32 != null) {
					//
					ole32.CoTaskMemFree(pbr.getValue());
					//
				} // if
					//
			} // try
				//
		} // if
			//
		return null;
		//
	}

	private static String getWideString(final Pointer instance, final long offset) {
		return instance != null ? instance.getWideString(offset) : null;
	}

	private static File getFileZillaSiteManagerXmlFile(final File folder) {
		//
		if (Boolean.logicalAnd(exists(folder), isDirectory(folder))) {
			//
			final File fileZilla = testAndApply(x -> x != null && x.length == 1, folder.listFiles((dir, name) -> {
				//
				return Objects.equals(name, "FileZilla");
				//
			}), x -> ArrayUtils.get(x, 0), null);
			//
			if (Boolean.logicalAnd(exists(fileZilla), isDirectory(fileZilla))) {
				//
				return testAndApply(x -> x != null && x.length == 1, fileZilla.listFiles((dir, name) -> {
					//
					return Objects.equals(name, "sitemanager.xml");
					//
				}), x -> ArrayUtils.get(x, 0), null);
				//
			} // if
				//
		} // if
			//
		return null;
		//
	}

	private static boolean isDirectory(final File instance) {
		return instance != null && instance.getPath() != null && instance.isDirectory();
	}

	private static void setText(final Object instance, final Map<?, ?> map) {
		//
		if (entrySet(map) == null || entrySet(map).iterator() == null) {
			//
			return;
			//
		} // if
			//
		JTextComponent jtc = null;
		//
		String value = null;
		//
		for (final Entry<?, ?> entry : entrySet(map)) {
			//
			if ((jtc = cast(JTextComponent.class,
					testAndApply((a, b) -> Boolean.logicalAnd(a != null, b != null), instance,
							testAndApply(x -> size(x) == 1,
									collect(filter(
											stream(testAndApply(Objects::nonNull, getClass(instance),
													FieldUtils::getAllFieldsList, null)),
											f -> Objects.equals(getName(f), Objects.toString(getKey(entry)))),
											Collectors.toList()),
									x -> get(x, 0), null),
							Narcissus::getField, null))) != null) {
				//
				if (Boolean.logicalAnd(
						Boolean.logicalAnd(isWindows(),
								isAnnotationPresent(testAndApply(x -> size(x) == 1,
										collect(filter(
												stream(testAndApply(Objects::nonNull, getClass(instance),
														FieldUtils::getAllFieldsList, null)),
												f -> Objects.equals(getName(f), getKey(entry))), Collectors.toList()),
										x -> get(x, 0), null), Password.class)),
						StringUtils.isNotEmpty(value = Objects.toString(getValue(entry))))) {
					//
					try {
						//
						value = testAndApply(Objects::nonNull,
								Crypt32Util.cryptUnprotectData(decode(Base64.getDecoder(), value)), String::new, null);
						//
					} catch (final Win32Exception e) {
						//
						continue;
						//
					} // try
						//
				} // if
					//
				setText(jtc, value);
				//
			} else {
				//
				throw new RuntimeException();
				//
			} // if
				//
		} // for
			//
	}

	private static void setText(final JTextComponent instance, final String text) {
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
						f -> Objects.equals(getName(f), "model")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.setText(text);
			//
		} // if
			//
	}

	private static void setText(final JLabel instance, final String text) {
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
						f -> Objects.equals(getName(f), OBJECT_LOCK)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.setText(text);
			//
		} // if
			//
	}

	private static boolean isAnnotationPresent(final AnnotatedElement instance,
			final Class<? extends Annotation> annotationClass) {
		return instance != null && instance.isAnnotationPresent(annotationClass);
	}

	private static byte[] decode(final Decoder instance, final String string) {
		//
		if (instance == null || string == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(string), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(string, field) != null ? instance.decode(string) : null;
		//
	}

	private static DocumentListener createDocumentListener(final JTextComponent jTextComponent,
			final Border borderDefault, final Border borderRed) {
		//
		return new DocumentListener() {

			@Override
			public void insertUpdate(final DocumentEvent evt) {
				validate();
			}

			@Override
			public void removeUpdate(final DocumentEvent evt) {
				validate();
			}

			@Override
			public void changedUpdate(final DocumentEvent evt) {
				validate();
			}

			private void validate() {
				//
				final String text = getText(jTextComponent);
				//
				if (StringUtils.isEmpty(text) || isValid(UrlValidator.getInstance(), text)) {
					//
					setBorder(jTextComponent, borderDefault);
					//
				} else {
					//
					setBorder(jTextComponent, borderRed);
					//
				} // if
					//
			}

		};
		//
	}

	private static <K, V> Collection<Entry<K, V>> entrySet(final Map<K, V> instance) {
		return instance != null ? instance.entrySet() : null;
	}

	private static void perform(final SshClient sshClient, final Document document, final String url,
			final File tempFile) throws Exception {
		//
		final XPath xp = newXPath(XPathFactory.newInstance());
		//
		final NodeList nodeList1 = cast(NodeList.class, evaluate(xp, "/*/config", document, XPathConstants.NODESET));
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
		for (int i = 0; i < getLength(nodeList1); i++) {
			//
			if ((node1 = item(nodeList1, i)) == null) {
				//
				continue;
				//
			} // if
				//
			(config = new Config()).hostAndPort = fromParts(
					getNodeValue(getNamedItem(attributes = getAttributes(node1), "host")),
					NumberUtils.toInt(getNodeValue(getNamedItem(attributes, "port")), 22));
			//
			config.basicCredentialsProvider = new BasicCredentialsImpl(getNodeValue(getNamedItem(attributes, "user")),
					getNodeValue(getNamedItem(attributes, PASSWORD)));
			//
			config.publicKey = testAndApply(Objects::nonNull, getNodeValue(getNamedItem(attributes, "publicKey")),
					File::new, null);
			//
			config.keytool = getNodeValue(getNamedItem(attributes, KEYTOOL));
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
				perform(sshClient, config, tempFile, url, md = ObjectUtils.getIfNull(md, () -> getMessageDigest(SHA1)),
						LOG);
				//
			} // for
				//
		} // for
			//
	}

	private static void addDocumentListener(final javax.swing.text.Document instance,
			final DocumentListener documentListener) {
		if (instance != null) {
			instance.addDocumentListener(documentListener);
		}
	}

	private static javax.swing.text.Document getDocument(final JTextComponent instance) {
		return instance != null ? instance.getDocument() : null;
	}

	private static void setBorder(final JComponent instance, final Border border) {
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
						f -> Objects.equals(getName(f), OBJECT_LOCK)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.setBorder(border);
			//
		} // if
			//
	}

	private static Border getBorder(final JTextComponent instance) {
		return instance != null ? instance.getBorder() : null;
	}

	private static KeyListener createKeyListener() {
		//
		return new KeyAdapter() {

			@Override
			public void keyTyped(final KeyEvent evt) {
				//
				if (evt == null) {
					//
					return;
					//
				} // if
					//
				final char c = evt.getKeyChar();
				//
				if (!((c >= '0') && (c <= '9') || (c == KeyEvent.VK_BACK_SPACE) || (c == KeyEvent.VK_DELETE))) {
					//
					evt.consume();
					//
				} // if
					//
			}

		};
		//
	}

	private static KeyListener createKeyListener2(final KeyStoreCertificateSshUpdater instance) {
		//
		return new KeyAdapter() {

			@Override
			public void keyPressed(final KeyEvent evt) {
				//
				if (evt == null || instance == null) {
					//
					return;
					//
				} // if
					//
				final Stream<Field> stream = testAndApply(Objects::nonNull,
						getDeclaredFields(KeyStoreCertificateSshUpdater.class), Arrays::stream, null);
				//
				final Map<String, String> m = collect(
						map(filter(stream, f -> isAssignableFrom(JTextComponent.class, getType(f))),
								f -> Pair.of(getName(f), getText(cast(JTextComponent.class,
										testAndApply(KeyStoreCertificateSshUpdater::isStatic, f,
												Narcissus::getStaticField, x -> Narcissus.getField(instance, x)))))),
						Collectors.toMap(KeyStoreCertificateSshUpdater::getKey,
								KeyStoreCertificateSshUpdater::getValue));
				//
				if (((evt.getModifiersEx() & InputEvent.CTRL_DOWN_MASK) != 0 && evt.getKeyCode() == KeyEvent.VK_X)
						&& (instance.map == null || !Objects.equals(instance.map, m))) {
					//
					instance.map = m;
					//
				} // if
					//
			}

		};
		//
	}

	private static void addKeyListener(final Component instance, final KeyListener keyListener) {
		if (instance != null) {
			instance.addKeyListener(keyListener);
		}
	}

	private static javax.swing.text.Document createDocument(final JTextComponent jTextComponent,
			final Number maxNumber) {
		//
		return new PlainDocument() {
			@Override
			public void insertString(final int offset, final String string, final AttributeSet attributeSet)
					throws BadLocationException {
				//
				if ((getLength() + StringUtils.length(string)) <= StringUtils.length(Objects.toString(maxNumber))) {
					//
					final StringBuilder sb = testAndApply(Objects::nonNull,
							KeyStoreCertificateSshUpdater.getText(jTextComponent), StringBuilder::new, null);
					//
					if (NumberUtils.isDigits(Objects.toString(insert(sb, offset, string))) && maxNumber != null
							&& NumberUtils.toInt(Objects.toString(sb)) > intValue(maxNumber, 0)) {
						//
						return;
						//
					} // if
						//
					super.insertString(offset, string, attributeSet);
					//
				} // if
					//
			}
		};
		//
	}

	private static void setDocument(final JTextComponent instance, final javax.swing.text.Document document) {
		if (instance != null && instance.getComponentOrientation() != null) {
			instance.setDocument(document);
		}
	}

	private static Collection<Integer> getPorts() throws IOException {

		final Collection<Integer> ports = new ArrayList<>();
		//
		try (final InputStream is = KeyStoreCertificateSshUpdater.class.getResourceAsStream(
				StringUtils.join("/", replace(Strings.CS, getName(InetSocketAddress.class), ".", "/"), ".class"))) {
			//
			new ClassReader(is).accept(new ClassVisitor(Opcodes.ASM9) {

				@Override
				public MethodVisitor visitMethod(final int access, final String name, final String descriptor,
						final String signature, final String[] exceptions) {
					//
					if (Objects.equals(name, "checkPort")) {
						//
						return new MethodVisitor(Opcodes.ASM9) {

							private Object ldc = null;

							@Override
							public void visitJumpInsn(final int opcode, final Label label) {
								//
								Number number = null;
								//
								if (opcode == Opcodes.IFLT) {
									//
									add(ports, 0);
									//
								} else if (opcode == Opcodes.IF_ICMPLE && (number = cast(Number.class, ldc)) != null) {
									//
									add(ports, intValue(number, 0));
									//
								} else {
									//
									throw new RuntimeException();
									//
								} // if
									//
							}

							@Override
							public void visitLdcInsn(final Object value) {
								//
								ldc = value;
								//
							}

						};
						//
					} // if
						//
					return super.visitMethod(access, name, descriptor, signature, exceptions);
					//
				}

			}, 0);
			//
		} // try
			//
		return ports;
		//
	}

	private static StringBuilder insert(final StringBuilder instance, final int offset, final String string) {
		//
		if (instance == null) {
			//
			return instance;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.insert(offset, string)
				: instance;
		//
	}

	private static int intValue(final Number instance, final int defaultValue) {
		return instance != null ? instance.intValue() : defaultValue;
	}

	private static String replace(final Strings instance, final String text, final String searchString,
			final String replacement) {
		//
		if (instance == null || text == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(text), FieldUtils::getAllFieldsList, null)),
						x -> Objects.equals(getName(x), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(text, field) != null
				? instance.replace(text, searchString, replacement)
				: null;
		//
	}

	private static Class<?> getType(final Field instance) {
		return instance != null ? instance.getType() : null;
	}

	private static boolean isAssignableFrom(final Class<?> a, final Class<?> b) {
		return a != null && b != null && a.isAssignableFrom(b);
	}

	private static <T> void forEach(final Stream<T> instance, final Consumer<? super T> action) {
		if (instance != null) {
			instance.forEach(action);
		}
	}

	private static <T, R> Stream<R> map(final Stream<T> instance, final Function<? super T, ? extends R> mapper) {
		return instance != null ? instance.map(mapper) : null;
	}

	private static void addActionListener(final AbstractButton instance, final ActionListener actionListener) {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(FieldUtils.getAllFieldsList(getClass(instance)).stream(),
						f -> Objects.equals(getName(f), OBJECT_LOCK)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.addActionListener(actionListener);
			//
		} // if
			//
	}

	private static void setVisible(final Component instnace, final boolean visible) {
		if (instnace != null) {
			instnace.setVisible(visible);
		}
	}

	private static void pack(final JFrame instance) {
		//
		if (instance == null || GraphicsEnvironment.isHeadless()) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(FieldUtils.getAllFieldsList(getClass(instance)).stream(),
						f -> Objects.equals(getName(f), OBJECT_LOCK)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.pack();
			//
		} // if
			//
	}

	private static void add(final Container instance, final Component comp) {
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
						x -> Objects.equals(getName(x), "component")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.add(comp);
			//
		} // if
			//
	}

	private static void setDefaultCloseOperation(final JFrame instance, final int operation) {
		if (instance != null) {
			instance.setDefaultCloseOperation(operation);
		}
	}

	private static <T> T getAsBooleanAndGet(final BooleanSupplier booleanSupplier, final Supplier<T> supplier) {
		return booleanSupplier != null && booleanSupplier.getAsBoolean() ? get(supplier) : null;
	}

	private static <T> T get(final Supplier<T> instance) {
		return instance != null ? instance.get() : null;
	}

	private static File createTempFile(final String prefix, final String suffix) {
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
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(prefix), FieldUtils::getAllFieldsList, null)),
						x -> Objects.equals(getName(x), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return cast(File.class, testAndApply(
				x -> isStatic(x) && prefix != null && (field == null || Narcissus.getField(prefix, field) != null),
				testAndApply(x -> size(x) == 1, ms, x -> get(x, 0), null),
				x -> Narcissus.invokeStaticMethod(x, prefix, suffix), null));
		//
	}

	@Override
	public void actionPerformed(final ActionEvent evt) {
		//
		final Object source = getSource(evt);
		//
		if (Objects.equals(source, btnPublicKey)) {
			//
			final JFileChooser jfc = new JFileChooser();
			//
			if (!GraphicsEnvironment.isHeadless() && !isTestMode()
					&& jfc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
				//
				final File file = jfc.getSelectedFile();
				//
				setText(tfPublicKey, exists(file) && isFile(file) ? getAbsolutePath(file) : null);
				//
			} // if
				//
		} else if (Objects.equals(source, btnExecute)) {
			//
			final File tempFile = createTempFile(nextAlphabetic(RandomStringUtils.secure(), 3), null);
			//
			try (final SshClient sshClient = SshClient.setUpDefaultClient()) {
				//
				start(sshClient);
				//
				final Config config = new Config();
				//
				config.hostAndPort = testAndApply(Objects::nonNull, getText(tfHost),
						x -> HostAndPort.fromParts(x, NumberUtils.toInt(getText(tfPort), SshConstants.DEFAULT_PORT)),
						null);
				//
				config.basicCredentialsProvider = new BasicCredentialsImpl(getText(tfUsername), getText(tfPassword));
				//
				config.publicKey = testAndApply(Objects::nonNull, getText(tfPublicKey), File::new, null);
				//
				config.keytool = getText(tfKeyTool);
				//
				config.keyStorePathPassword = Pair.of(getText(tfKeyStorePath), getText(tfKeyStorePassword));
				//
				perform(sshClient, config, tempFile, getText(tfUrl), getMessageDigest(SHA1), LOG);
				//
			} catch (final Exception e) {
				//
				error(LOG, getMessage(e), e);
				//
			} finally {
				//
				FileUtils.deleteQuietly(tempFile);
				//
			} // try
				//
		} else if (Objects.equals(source, jcb)) {
			//
			final FileZillaProfile zfp = cast(FileZillaProfile.class, getSelectedItem(jcb));
			//
			final HostAndPort hostAndPort = FileZillaProfile.getHostAndPort(zfp);
			//
			setText(tfHost, getHost(hostAndPort));
			//
			setText(tfPort, Integer.toString(testAndApplyAsInt(KeyStoreCertificateSshUpdater::hasPort, hostAndPort,
					x -> getPort(x, SshConstants.DEFAULT_PORT), null, SshConstants.DEFAULT_PORT)));
			//
			if (zfp != null) {
				//
				final BasicCredentialsProvider basicCredentialsProvider = zfp.basicCredentialsProvider;
				//
				setText(tfUsername, getUsername(basicCredentialsProvider));
				//
				setText(tfPassword, getPassword(basicCredentialsProvider));
				//
				setText(tfPublicKey, getAbsolutePath(zfp.keyFile));
				//
			} // if
				//
		} // if
			//
	}

	private static Object getSelectedItem(final JComboBox<?> instance) {
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
						x -> Objects.equals(getName(x), "dataModel")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getSelectedItem() : null;
		//
	}

	private static Object getSource(final EventObject instance) {
		return instance != null ? instance.getSource() : null;
	}

	private static boolean isTestMode() {
		try {
			return Class.forName("org.testng.annotations.Test") != null;
		} catch (final ClassNotFoundException e) {
			return false;
		}
	}

	private static String getText(final JTextComponent instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		try {
			//
			if (Narcissus.getField(instance, Narcissus.findField(getClass(instance), "model")) == null) {
				//
				return null;
				//
			} // if
				//
		} catch (final NoSuchFieldException e) {
			//
			throw new RuntimeException(e);
			//
		} // try
			//
		return instance.getText();
		//
	}

	private static boolean isGui() {
		//
		if (Objects.equals(getName(getClass(FileSystems.getDefault())), "sun.nio.fs.MacOSXFileSystem")) {
			//
			return System.console() == null;
			//
		} // if
			//
		if (isWindows()) {
			//
			final Matcher matcher = matcher(Pattern.compile("\\d+"), getName(ManagementFactory.getRuntimeMXBean()));
			//
			if (find(matcher)) {
				//
				return BooleanUtils.toBooleanDefaultIfNull(testAndApply(NumberUtils::isDigits, group(matcher),
						x -> endsWith(Kernel32Util.QueryFullProcessImageName(NumberUtils.toInt(x), 0), "javaw.exe"),
						null), false);
				//
			} // if
				//
		} // if
			//
		return false;
		//
	}

	private static boolean isWindows() {
		return Objects.equals(getName(getClass(FileSystems.getDefault())), "sun.nio.fs.WindowsFileSystem");
	}

	private static boolean endsWith(final String instance, final String suffix) {
		//
		if (instance == null || suffix == null) {
			//
			return false;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						x -> Objects.equals(getName(x), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return (field == null || Boolean.logicalAnd(Narcissus.getField(instance, field) != null,
				Narcissus.getField(suffix, field) != null)) && instance.endsWith(suffix);
		//
	}

	private static Matcher matcher(final Pattern instance, final CharSequence input) {
		//
		if (instance == null || input == null) {
			//
			return null;
			//
		} // if
			//
		final Field normalizedPattern = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "normalizedPattern")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		final Field value = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(input), FieldUtils::getAllFieldsList, null)),
						x -> Objects.equals(getName(x), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return (normalizedPattern == null || Narcissus.getField(instance, normalizedPattern) != null)
				&& (value == null || Narcissus.getField(input, value) != null) ? instance.matcher(input) : null;
		//
	}

	private static String group(final MatchResult instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field first = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "first")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (Objects.equals(getType(first), Integer.TYPE)) {
			//
			return Narcissus.getIntField(instance, first) >= 0 ? instance.group() : null;
			//
		} // if
			//
		return instance.group();
		//
	}

	private static String getName(final RuntimeMXBean instance) {
		return instance != null ? instance.getName() : null;
	}

	private static boolean find(final Matcher instance) {
		//
		if (instance == null) {
			//
			return false;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "groups")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return (field == null || Narcissus.getField(instance, field) != null) && instance.find();
		//
	}

	private static String getName(final Class<?> instance) {
		return instance != null ? instance.getName() : null;
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

		private HostAndPort getHostAndPort() {
			return hostAndPort;
		}

		private static HostAndPort getHostAndPort(final Config instnace) {
			return instnace != null ? instnace.getHostAndPort() : null;
		}

	}

	private static void perform(final SshClient sshClient, final Config config, final File tempFile, final String url,
			final MessageDigest md, final Logger logger) throws Exception {
		//
		final String algorithm = getAlgorithm(md);
		//
		final int length = Math.max(StringUtils.length(algorithm), 9);
		//
		final HostAndPort hostAndPort = Config.getHostAndPort(config);
		//
		final String host = getHost(hostAndPort);
		//
		final int port = testAndApplyAsInt(KeyStoreCertificateSshUpdater::hasPort, hostAndPort,
				x -> getPort(x, SshConstants.DEFAULT_PORT), null, SshConstants.DEFAULT_PORT);
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
			testAndAccept(StringUtils::isNotEmpty, getPassword(basicCredentialsProvider),
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
							if (!Boolean.parseBoolean(StringUtils.trim(executeRemoteCommand(clientSession,
									String.join("", "[ -f ", StringUtils.trim(executeRemoteCommand(clientSession,
											String.join("", "echo ", file, ".`date -r ", file, " ", dateFormat, "`"))),
											" ] && echo true||echo false"))))) {
								//
								info(logger, "KeyStore Backup Failed.");
								//
								return;
								//
							} // if
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
					final File filePem = new File(String.join(".", replace(Strings.CS, alias, "*", ""), "pem"));
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
					info(logger, format, StringUtils.rightPad(KEYTOOL, length), keytool);
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

	private static <T> int testAndApplyAsInt(final Predicate<T> predicate, final T value,
			final ToIntFunction<T> functionTrue, final ToIntFunction<T> functionFalse, final int defaultValue) {
		return test(predicate, value) ? applyAsInt(functionTrue, value, defaultValue)
				: applyAsInt(functionFalse, value, defaultValue);
	}

	private static <T> int applyAsInt(final ToIntFunction<T> instance, final T value, final int defaultValue) {
		return instance != null ? instance.applyAsInt(value) : defaultValue;
	}

	private static boolean hasPort(final HostAndPort instance) {
		return instance != null && instance.hasPort();
	}

	private static int getPort(final HostAndPort instance, final int defaultValue) {
		return instance != null && hasPort(instance) ? instance.getPort() : defaultValue;
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
				|| (Objects.equals(getType(field), Boolean.TYPE) && Narcissus.getBooleanField(instance, field))) {
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
				|| (Objects.equals(getType(field), Boolean.TYPE) && Narcissus.getBooleanField(instance, field)))
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
			return (field == null || Narcissus.getField(x, field) != null) && isValid(UrlValidator.getInstance(), x);
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

	private static boolean isValid(final UrlValidator instance, final String value) {
		//
		if (instance == null || value == null) {
			//
			return false;
			//
		} // if
			//
		final Field field = testAndApply(y -> size(y) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(value), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				y -> get(y, 0), null);
		//
		return (field == null || Narcissus.getField(value, field) != null) && instance.isValid(value);
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

	private static <T, R> R collect(final Stream<T> instance, final Supplier<R> supplier,
			final BiConsumer<R, ? super T> accumulator, final BiConsumer<R, R> combiner) {
		//
		return instance != null ? instance.collect(supplier, accumulator, combiner) : null;
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

	@Override
	public void changedUpdate(final DocumentEvent evt) {
		//
		update();
		//
	}

	private void update() {
		//
		final Map<String, String> m = toMap(this);
		//
		if (!isTestMode() && (this.map == null || !Objects.equals(this.map, m))) {
			//
			write(new File("KeyStoreCertificateSshUpdater.properties"), m);
			//
		} // if
			//
	}

	private static void write(final File file, final Map<?, ?> map) {
		//
		if (exists(file) && !isFile(file)) {
			//
			return;
			//
		} // if
			//
		try (final OutputStream os = testAndApply(x -> x != null && x.getPath() != null, file, FileOutputStream::new,
				null)) {
			//
			final Properties properties = new Properties();
			//
			forEach(stream(entrySet(map)), x -> {
				//
				final Object value = getValue(x);
				//
				if (value != null) {
					//
					put(properties, getKey(x), value);
					//
				} // if
					//
			});
			//
			testAndAccept(Objects::nonNull, os, x -> properties.store(x, null));
			//
		} catch (final IOException e) {
			//
			error(LOG, getMessage(e), e);
			//
		} // try
			//
	}

	private static Map<String, String> toMap(final Object instance) {
		//
		final Stream<Field> stream1 = testAndApply(Objects::nonNull, getDeclaredFields(getClass(instance)),
				Arrays::stream, null);
		//
		final Stream<Entry<String, String>> stream2 = map(
				filter(stream1, f -> isAssignableFrom(JTextComponent.class, getType(f))), f -> {
					//
					String value = getText(
							cast(JTextComponent.class, testAndApply(KeyStoreCertificateSshUpdater::isStatic, f,
									Narcissus::getStaticField, x -> Narcissus.getField(instance, x))));
					//
					if (isWindows() && isAnnotationPresent(f, Password.class)) {
						//
						value = encodeToString(Base64.getEncoder(), Crypt32Util.cryptProtectData(getBytes(value)));
						//
					} // if
						//
					return Pair.of(getName(f), value);
					//
				});
		//
		return collect(stream2, LinkedHashMap::new, (a, b) -> put(a, getKey(b), getValue(b)), Map::putAll);
		//
	}

	private static String encodeToString(final Encoder instance, final byte[] bs) {
		return instance != null ? instance.encodeToString(bs) : null;
	}

	private static byte[] getBytes(final String instance) {
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
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getBytes() : null;
		//
	}

	private static Field[] getDeclaredFields(final Class<?> instance) {
		return instance != null ? instance.getDeclaredFields() : null;
	}

	@Override
	public void insertUpdate(final DocumentEvent evt) {
		//
		update();
		//
	}

	@Override
	public void removeUpdate(final DocumentEvent evt) {
		//
		update();
		//
	}

}