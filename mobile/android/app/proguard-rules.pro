# Keep JNI entry points and callback methods invoked from hogman_jni.c.
-keep class network.hogman.mobile.core.HogmanNative { *; }
-keep interface network.hogman.mobile.core.TunnelCallbackTarget { *; }
-keep class * implements network.hogman.mobile.core.TunnelCallbackTarget {
    public int protectFd(int);
    public int onTunnelReconfig(java.lang.String);
}
