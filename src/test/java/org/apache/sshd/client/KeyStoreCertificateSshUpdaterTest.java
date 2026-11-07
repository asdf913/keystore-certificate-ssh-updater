package org.apache.sshd.client;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.function.BiPredicate;
import java.util.function.BooleanSupplier;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.ToIntFunction;
import java.util.regex.MatchResult;
import java.util.stream.Stream;

import javax.net.ssl.HttpsURLConnection;
import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JTextField;
import javax.swing.text.JTextComponent;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.Strings;
import org.apache.commons.lang3.function.FailableBiFunction;
import org.apache.commons.lang3.function.FailableFunction;
import org.apache.commons.lang3.function.FailableSupplier;
import org.apache.commons.lang3.function.Suppliers;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionCreator;
import org.apache.sshd.common.auth.PasswordHolder;
import org.apache.sshd.common.auth.UsernameHolder;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceLoader;
import org.apache.sshd.common.future.VerifiableFuture;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.google.common.reflect.Reflection;

import io.github.toolfactory.narcissus.Narcissus;

class KeyStoreCertificateSshUpdaterTest {

	private static Method METHOD_ADD, METHOD_GET_NAME, METHOD_GET_CLASS, METHOD_NEW_DOCUMENT_BUILDER,
			METHOD_ADD_CHARACTER, METHOD_IS_STATIC, METHOD_CAST, METHOD_GET_AS_BOOLEAN_AND_GET,
			METHOD_IS_ASSIGNABLE_FROM = null;

	@BeforeClass
	static void beforeClass() throws NoSuchMethodException {
		//
		final Class<?> clz = KeyStoreCertificateSshUpdater.class;
		//
		(METHOD_ADD = clz.getDeclaredMethod("add", Collection.class, Object.class)).setAccessible(true);
		//
		(METHOD_GET_NAME = clz.getDeclaredMethod("getName", Member.class)).setAccessible(true);
		//
		(METHOD_GET_CLASS = clz.getDeclaredMethod("getClass", Object.class)).setAccessible(true);
		//
		(METHOD_NEW_DOCUMENT_BUILDER = clz.getDeclaredMethod("newDocumentBuilder", DocumentBuilderFactory.class))
				.setAccessible(true);
		//
		(METHOD_ADD_CHARACTER = clz.getDeclaredMethod("addCharacter", String.class, Integer.TYPE, Character.TYPE))
				.setAccessible(true);
		//
		(METHOD_IS_STATIC = clz.getDeclaredMethod("isStatic", Member.class)).setAccessible(true);
		//
		(METHOD_CAST = clz.getDeclaredMethod("cast", Class.class, Object.class)).setAccessible(true);
		//
		(METHOD_GET_AS_BOOLEAN_AND_GET = clz.getDeclaredMethod("getAsBooleanAndGet", BooleanSupplier.class,
				Supplier.class)).setAccessible(true);
		//
		(METHOD_IS_ASSIGNABLE_FROM = clz.getDeclaredMethod("isAssignableFrom", Class.class, Class.class))
				.setAccessible(true);
		//
	}

	private static class IH implements InvocationHandler {

		private Boolean add, test, containsKey, isSuccess, hasMoreElements, isOpened, getAsBoolean = null;

		private Integer size, length, modifiers, applyAsInt = null;

		private Short nodeType = null;

		@Override
		public Object invoke(final Object proxy, final Method method, final Object[] args) throws Throwable {
			//
			if (Objects.equals(getReturnType(method), Void.TYPE)) {
				//
				return null;
				//
			} // if
				//
			final String name = getName(method);
			//
			if (proxy instanceof Collection) {
				//
				if (Objects.equals(name, "add")) {
					//
					return add;
					//
				} else if (Objects.equals(name, "size")) {
					//
					return size;
					//
				} else if (Objects.equals(name, "stream")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof AuthFuture && Objects.equals(name, "isSuccess")) {
				//
				return isSuccess;
				//
			} else if (proxy instanceof OpenFuture) {
				//
				if (Objects.equals(name, "isOpened")) {
					//
					return isOpened;
					//
				} // if
					//
			} else if (proxy instanceof Member && Objects.equals(name, "getModifiers")) {
				//
				return modifiers;
				//
			} // if
				//
			if (proxy instanceof Member) {
				//
				if (Objects.equals(name, "getName")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof Map) {
				//
				if (Objects.equals(name, "get")) {
					//
					return null;
					//
				} else if (Objects.equals(name, "put")) {
					//
					return null;
					//
				} else if (Objects.equals(name, "containsKey")) {
					//
					return containsKey;
					//
				} // if
					//
			} else if (proxy instanceof List) {
				//
				if (Objects.equals(name, "get")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof Predicate) {
				//
				if (Objects.equals(name, "test")) {
					//
					return test;
					//
				} // if
					//
			} else if (proxy instanceof BiPredicate) {
				//
				if (Objects.equals(name, "test")) {
					//
					return test;
					//
				} // if
					//
			} else if (proxy instanceof Entry) {
				//
				if (contains(Arrays.asList("getValue", "getKey"), name)) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof FailableFunction) {
				//
				if (Objects.equals(name, "apply")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof FailableBiFunction) {
				//
				if (Objects.equals(name, "apply")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof Stream) {
				//
				if (Objects.equals(name, "collect")) {
					//
					return null;
					//
				} else if (Objects.equals(name, "map")) {
					//
					return null;
					//
				} else if (Objects.equals(name, "filter")) {
					//
					return proxy;
					//
				} // if
					//
			} else if (proxy instanceof SftpClient) {
				//
				if (Objects.equals(name, "read")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof ClientSessionCreator) {
				//
				if (Objects.equals(name, "connect")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof Node) {
				//
				if (contains(Arrays.asList("getAttributes", "getNodeValue", "getParentNode", "getNamespaceURI",
						"getLocalName"), name)) {
					//
					return null;
					//
				} else if (Objects.equals(name, "getNodeType")) {
					//
					return nodeType;
					//
				} // if
					//
			} else if (proxy instanceof ClientSession) {
				//
				if (contains(Arrays.asList("auth", "executeRemoteCommand", "createExecChannel"), name)) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof VerifiableFuture) {
				//
				if (Objects.equals(name, "verify")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof XPath) {
				//
				if (Objects.equals(name, "evaluate")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof NamedNodeMap) {
				//
				if (Objects.equals(name, "getNamedItem")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof SftpClientFactory) {
				//
				if (Objects.equals(name, "createSftpClient")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof KeyPairResourceLoader) {
				//
				if (Objects.equals(name, "loadKeyPairs")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof SessionHolder && Objects.equals(name, "getSession")) {
				//
				return null;
				//
			} else if (proxy instanceof UsernameHolder) {
				//
				if (Objects.equals(name, "getUsername")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof PasswordHolder) {
				//
				if (Objects.equals(name, "getPassword")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof NodeList) {
				//
				if (Objects.equals(name, "getLength")) {
					//
					return length;
					//
				} else if (Objects.equals(name, "item")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof Enumeration) {
				//
				if (Objects.equals(name, "hasMoreElements")) {
					//
					return hasMoreElements;
					//
				} else if (Objects.equals(name, "nextElement")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof FailableSupplier && Objects.equals(name, "get")) {
				//
				return null;
				//
			} else if (proxy instanceof ClientChannel && Objects.equals(name, "open")) {
				//
				return null;
				//
			} else if (proxy instanceof RuntimeMXBean && Objects.equals(name, "getName")) {
				//
				return null;
				//
			} else if (proxy instanceof MatchResult && Objects.equals(name, "group")) {
				//
				return null;
				//
			} else if (proxy instanceof BooleanSupplier && Objects.equals(name, "getAsBoolean")) {
				//
				return getAsBoolean;
				//
			} else if (proxy instanceof Supplier && Objects.equals(name, "get")) {
				//
				return null;
				//
			} else if (proxy instanceof ToIntFunction && Objects.equals(name, "applyAsInt")) {
				//
				return applyAsInt;
				//
			} // if
				//
			throw new Throwable(name);
			//
		}

	}

	private static Class<?> getReturnType(final Method instance) {
		return instance != null ? instance.getReturnType() : null;
	}

	private static String getName(final Member instance) throws Throwable {
		try {
			final Object obj = invoke(METHOD_GET_NAME, null, instance);
			if (obj == null) {
				return null;
			} else if (obj instanceof String) {
				return (String) obj;
			}
			throw new Throwable(Objects.toString(getClass(obj)));
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	private static Object invoke(final Method method, final Object instance, final Object... args)
			throws IllegalAccessException, InvocationTargetException {
		return method != null && method.getDeclaringClass() != null ? method.invoke(instance, args) : null;
	}

	private static Class<?> getClass(final Object instance) throws Throwable {
		try {
			final Object obj = invoke(METHOD_GET_CLASS, null, instance);
			if (obj == null) {
				return null;
			} else if (obj instanceof Class) {
				return (Class<?>) obj;
			}
			throw new Throwable(Objects.toString(getClass(obj)));
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	private KeyStoreCertificateSshUpdater instance = null;

	@BeforeMethod
	void beforeMethod() throws Throwable {
		//
		instance = cast(KeyStoreCertificateSshUpdater.class,
				Narcissus.allocateInstance(KeyStoreCertificateSshUpdater.class));
		//
	}

	private static <T> T cast(final Class<T> clz, final Object instance) throws Throwable {
		try {
			return (T) invoke(METHOD_CAST, null, clz, instance);
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	@Test
	void testNull() throws Throwable {
		//
		final Method[] ms = KeyStoreCertificateSshUpdater.class.getDeclaredMethods();
		//
		Method m = null;
		//
		Class<?>[] parameterTypes = null;
		//
		Class<?> parameterType = null;
		//
		Object result = null;
		//
		String toString, name = null;
		//
		Object[] os = null;
		//
		Collection<Object> collection = null;
		//
		for (int i = 0; ms != null && i < ms.length; i++) {
			//
			if ((m = ArrayUtils.get(ms, i)) == null || m.isSynthetic()
					|| (parameterTypes = m.getParameterTypes()) == null) {
				//
				continue;
				//
			} // if
				//
			clear(collection = ObjectUtils.getIfNull(collection, ArrayList::new));
			//
			for (int j = 0; j < parameterTypes.length; j++) {
				//
				if (Objects.equals(parameterType = ArrayUtils.get(parameterTypes, j), Integer.TYPE)) {
					//
					add(collection, Integer.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Boolean.TYPE)) {
					//
					add(collection, Boolean.FALSE);
					//
				} else if (Objects.equals(parameterType, Character.TYPE)) {
					//
					add(collection, Character.valueOf(' '));
					//
				} else {
					//
					add(collection, null);
					//
				} // if
					//
			} // for
				//
			os = toArray(collection);
			//
			toString = Objects.toString(m);
			//
			result = isStatic(m) ? Narcissus.invokeStaticMethod(m, os) : Narcissus.invokeMethod(instance, m, os);
			//
			if (contains(Arrays.asList(Integer.TYPE, Boolean.TYPE), getReturnType(m))
					|| Boolean.logicalAnd(Objects.equals(name = getName(m), "getPorts"), m.getParameterCount() == 0)
					|| Boolean.logicalAnd(Objects.equals(name, "createDocument"),
							Arrays.equals(parameterTypes, new Class<?>[] { JTextComponent.class, Number.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "createKeyListener"), m.getParameterCount() == 0)) {
				//
				Assert.assertNotNull(result, toString);
				//
			} else {
				//
				Assert.assertNull(result, toString);
				//
			} // if
				//
		} // for
			//
	}

	private static boolean contains(final Collection<?> instance, final Object item) {
		return instance != null && instance.contains(item);
	}

	private static void clear(final Collection<?> instance) {
		if (instance != null) {
			instance.clear();
		}
	}

	private static Object[] toArray(final Collection<?> instance) {
		return instance != null ? instance.toArray() : null;
	}

	private static <E> void add(final Collection<E> instance, final E item) throws Throwable {
		try {
			invoke(METHOD_ADD, null, instance, item);
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	@Test
	void testNotNull() throws Throwable {
		//
		final Method[] ms = KeyStoreCertificateSshUpdater.class.getDeclaredMethods();
		//
		Method m = null;
		//
		Class<?>[] parameterTypes = null;
		//
		Class<?> parameterType = null;
		//
		Object result = null;
		//
		String toString, name = null;
		//
		Object[] os = null;
		//
		Collection<Object> collection = null;
		//
		IH ih = null;
		//
		for (int i = 0; ms != null && i < ms.length; i++) {
			//
			if ((m = ArrayUtils.get(ms, i)) == null || m.isSynthetic()
					|| (parameterTypes = m.getParameterTypes()) == null) {
				//
				continue;
				//
			} // if
				//
			clear(collection = ObjectUtils.getIfNull(collection, ArrayList::new));
			//
			for (int j = 0; j < parameterTypes.length; j++) {
				//
				if (Objects.equals(parameterType = ArrayUtils.get(parameterTypes, j), Integer.TYPE)) {
					//
					add(collection, Integer.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Boolean.TYPE)) {
					//
					add(collection, Boolean.FALSE);
					//
				} else if (Objects.equals(parameterType, Character.TYPE)) {
					//
					add(collection, Character.valueOf(' '));
					//
				} else if (Objects.equals(parameterType, Class.class)) {
					//
					add(collection, Class.class);
					//
				} else if (Objects.equals(parameterType, DateFormat.class)) {
					//
					add(collection, Narcissus.allocateInstance(SimpleDateFormat.class));
					//
				} else if (Objects.equals(parameterType, HttpsURLConnection.class)) {
					//
					add(collection, Narcissus
							.allocateInstance(Class.forName("sun.net.www.protocol.https.HttpsURLConnectionImpl")));
					//
				} else if (Objects.equals(parameterType, Certificate.class)
						|| Objects.equals(parameterType, X509Certificate.class)) {
					//
					add(collection, Narcissus.allocateInstance(Class.forName("sun.security.x509.X509CertImpl")));
					//
				} else if (Objects.equals(parameterType, DocumentBuilder.class)) {
					//
					add(collection, Narcissus
							.allocateInstance(getClass(newDocumentBuilder(DocumentBuilderFactory.newInstance()))));
					//
				} else if (Objects.equals(parameterType, MessageDigest.class)) {
					//
					add(collection, Narcissus.allocateInstance(getClass(MessageDigest.getInstance("SHA-1"))));
					//
				} else if (Objects.equals(parameterType, DocumentBuilderFactory.class)) {
					//
					add(collection, Narcissus.allocateInstance(getClass(DocumentBuilderFactory.newInstance())));
					//
				} else if (Objects.equals(parameterType, InputStream.class)) {
					//
					add(collection, new ByteArrayInputStream(new byte[] {}));
					//
				} else if (Objects.equals(parameterType, OutputStream.class)) {
					//
					add(collection, new ByteArrayOutputStream());
					//
				} else if (Objects.equals(parameterType, XPathFactory.class)) {
					//
					add(collection, Narcissus.allocateInstance(getClass(XPathFactory.newInstance())));
					//
				} else if (Objects.equals(parameterType, Duration.class)) {
					//
					add(collection, Narcissus.allocateInstance(getClass(Duration.ofSeconds(0))));
					//
				} else if (Objects.equals(parameterType, JTextComponent.class)
						|| Objects.equals(parameterType, Component.class)
						|| Objects.equals(parameterType, JComponent.class)) {
					//
					add(collection, Narcissus.allocateInstance(JTextField.class));
					//
				} else if (Objects.equals(parameterType, AbstractButton.class)) {
					//
					add(collection, Narcissus.allocateInstance(JButton.class));
					//
				} else if (Objects.equals(parameterType, Number.class)) {
					//
					add(collection, Narcissus.allocateInstance(Integer.class));
					//
				} else if (Objects.equals(parameterType, Strings.class)) {
					//
					add(collection, Narcissus.allocateInstance(getClass(Strings.CI)));
					//
				} else if (parameterType != null && parameterType.isInterface()) {
					//
					if ((ih = ObjectUtils.getIfNull(ih, IH::new)) != null) {
						//
						final List<Field> fs = FieldUtils.getAllFieldsList(getClass(ih));
						//
						Field f = null;
						//
						for (int k = 0; fs != null && k < fs.size(); k++) {
							//
							if ((f = fs.get(k)) == null) {
								//
								continue;
								//
							} // if
								//
							final Class<?> type = f.getType();
							//
							if (Objects.equals(type, Boolean.class)) {
								//
								Narcissus.setField(ih, f, Boolean.TRUE);
								//
							} else if (Objects.equals(type, Integer.class)) {
								//
								Narcissus.setField(ih, f, Integer.valueOf(0));
								//
							} else if (Objects.equals(type, Short.class)) {
								//
								Narcissus.setField(ih, f, Short.valueOf((short) 0));
								//
							} // if
								//
						} // for
							//
					} // if
						//
					add(collection, Reflection.newProxy(parameterType, ih));
					//
				} else if (parameterType != null && parameterType.isArray()) {
					//
					add(collection, Array.newInstance(parameterType.getComponentType(), 0));
					//
				} else {
					//
					add(collection, Narcissus.allocateInstance(parameterType));
					//
				} // if
					//
			} // for
				//
			os = toArray(collection);
			//
			toString = Objects.toString(m);
			//
			result = isStatic(m) ? Narcissus.invokeStaticMethod(m, os) : Narcissus.invokeMethod(instance, m, os);
			//
			if (contains(Arrays.asList(Integer.TYPE, Boolean.TYPE), getReturnType(m))
					|| Boolean.logicalAnd(Objects.equals(name = getName(m), "getClass"),
							Arrays.equals(parameterTypes, new Class<?>[] { Object.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "filter"),
							Arrays.equals(parameterTypes, new Class<?>[] { Stream.class, Predicate.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "isOpened"),
							Arrays.equals(parameterTypes, new Class<?>[] { OpenFuture.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "getName"),
							Arrays.equals(parameterTypes, new Class<?>[] { Class.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "insert"),
							Arrays.equals(parameterTypes,
									new Class<?>[] { StringBuilder.class, Integer.TYPE, String.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "getPorts"), m.getParameterCount() == 0)
					|| Boolean.logicalAnd(Objects.equals(name, "createDocument"),
							Arrays.equals(parameterTypes, new Class<?>[] { JTextComponent.class, Number.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "createKeyListener"), m.getParameterCount() == 0)) {
				//
				Assert.assertNotNull(result, toString);
				//
			} else {
				//
				Assert.assertNull(result, toString);
				//
			} // if
				//
		} // for
			//
	}

	private static boolean isStatic(final Member instance) throws Throwable {
		try {
			final Object obj = invoke(METHOD_IS_STATIC, null, instance);
			if (obj instanceof Boolean) {
				return ((Boolean) obj).booleanValue();
			}
			throw new Throwable(Objects.toString(getClass(obj)));
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	private static DocumentBuilder newDocumentBuilder(final DocumentBuilderFactory instance) throws Throwable {
		try {
			final Object obj = invoke(METHOD_NEW_DOCUMENT_BUILDER, null, instance);
			if (obj == null) {
				return null;
			} else if (obj instanceof DocumentBuilder) {
				return (DocumentBuilder) obj;
			}
			throw new Throwable(Objects.toString(getClass(obj)));
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	@Test
	void testAddCharacter() throws Throwable {
		//
		Assert.assertEquals(addCharacter("1234", 2, ':'), "12:34");
		//
	}

	private static String addCharacter(final String instance, final int count, final char c) throws Throwable {
		try {
			final Object obj = invoke(METHOD_ADD_CHARACTER, null, instance, count, c);
			if (obj == null) {
				return null;
			} else if (obj instanceof String) {
				return (String) obj;
			}
			throw new Throwable(Objects.toString(getClass(obj)));
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	@Test
	public void testActionPerformed() throws IllegalAccessException {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Object btnExecute = new JButton();
		//
		FieldUtils.writeDeclaredField(instance, "btnExecute", btnExecute, true);
		//
		instance.actionPerformed(new ActionEvent(btnExecute, 0, null));
		//
	}

	@Test
	void testGetAsBooleanAndGet() throws Throwable {
		//
		Assert.assertNull(getAsBooleanAndGet(() -> false, null));
		//
		Assert.assertNull(getAsBooleanAndGet(() -> true, null));
		//
		Assert.assertNull(getAsBooleanAndGet(() -> true, Suppliers.nul()));
		//
	}

	private static <T> T getAsBooleanAndGet(final BooleanSupplier booleanSupplier, final Supplier<T> supplier)
			throws Throwable {
		try {
			return (T) invoke(METHOD_GET_AS_BOOLEAN_AND_GET, null, booleanSupplier, supplier);
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	@Test
	void testIsAssignableFrom() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertEquals(invoke(METHOD_IS_ASSIGNABLE_FROM, null, Object.class, null), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_ASSIGNABLE_FROM, null, String.class, Object.class), Boolean.FALSE);
		//
	}

}