package com.boeyu.systemmanagerlib;

import android.Manifest;
import android.accessibilityservice.AccessibilityService;
import android.app.ActivityManager;
import android.app.AlarmManager;
import android.app.AppOpsManager;
import android.app.PendingIntent;
import android.app.Service;
import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.IPackageDataObserver;
import android.content.pm.IPackageDeleteObserver;
import android.content.pm.IPackageInstallObserver;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.hardware.usb.UsbManager;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.PowerManager;
import android.os.RemoteException;
import android.os.SystemClock;
import android.os.UserHandle;
import android.os.UserManager;
import android.provider.Settings;
import android.support.annotation.RequiresApi;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;


/**
 * Created by laiqu on 2019-12-26.
 */

public class SystemManager {

    private static final String TAG = "fly235";

    /**
     * op值，参考AppOpsManager类的声明
     */
    public static final int OP_NONE = -1;
    public static final int OP_COARSE_LOCATION = 0;
    public static final int OP_FINE_LOCATION = 1;
    public static final int OP_GPS = 2;
    public static final int OP_VIBRATE = 3;
    public static final int OP_READ_CONTACTS = 4;
    public static final int OP_WRITE_CONTACTS = 5;
    public static final int OP_READ_CALL_LOG = 6;
    public static final int OP_WRITE_CALL_LOG = 7;
    public static final int OP_READ_CALENDAR = 8;
    public static final int OP_WRITE_CALENDAR = 9;
    public static final int OP_WIFI_SCAN = 10;
    public static final int OP_POST_NOTIFICATION = 11;
    public static final int OP_NEIGHBORING_CELLS = 12;
    public static final int OP_CALL_PHONE = 13;
    public static final int OP_READ_SMS = 14;
    public static final int OP_WRITE_SMS = 15;
    public static final int OP_RECEIVE_SMS = 16;
    public static final int OP_RECEIVE_EMERGECY_SMS = 17;
    public static final int OP_RECEIVE_MMS = 18;
    public static final int OP_RECEIVE_WAP_PUSH = 19;
    public static final int OP_SEND_SMS = 20;
    public static final int OP_READ_ICC_SMS = 21;
    public static final int OP_WRITE_ICC_SMS = 22;
    public static final int OP_WRITE_SETTINGS = 23;
    public static final int OP_SYSTEM_ALERT_WINDOW = 24;
    public static final int OP_ACCESS_NOTIFICATIONS = 25;
    public static final int OP_CAMERA = 26;
    public static final int OP_RECORD_AUDIO = 27;
    public static final int OP_PLAY_AUDIO = 28;
    public static final int OP_READ_CLIPBOARD = 29;
    public static final int OP_WRITE_CLIPBOARD = 30;
    public static final int OP_TAKE_MEDIA_BUTTONS = 31;
    public static final int OP_TAKE_AUDIO_FOCUS = 32;
    public static final int OP_AUDIO_MASTER_VOLUME = 33;
    public static final int OP_AUDIO_VOICE_VOLUME = 34;
    public static final int OP_AUDIO_RING_VOLUME = 35;
    public static final int OP_AUDIO_MEDIA_VOLUME = 36;
    public static final int OP_AUDIO_ALARM_VOLUME = 37;
    public static final int OP_AUDIO_NOTIFICATION_VOLUME = 38;
    public static final int OP_AUDIO_BLUETOOTH_VOLUME = 39;
    public static final int OP_WAKE_LOCK = 40;
    public static final int OP_MONITOR_LOCATION = 41;
    public static final int OP_MONITOR_HIGH_POWER_LOCATION = 42;
    public static final int OP_GET_USAGE_STATS = 43;
    public static final int OP_MUTE_MICROPHONE = 44;
    public static final int OP_TOAST_WINDOW = 45;
    public static final int OP_PROJECT_MEDIA = 46;
    public static final int OP_ACTIVATE_VPN = 47;
    public static final int OP_WRITE_WALLPAPER = 48;
    public static final int OP_ASSIST_STRUCTURE = 49;
    public static final int OP_ASSIST_SCREENSHOT = 50;
    public static final int OP_READ_PHONE_STATE = 51;
    public static final int OP_ADD_VOICEMAIL = 52;
    public static final int OP_USE_SIP = 53;
    public static final int OP_PROCESS_OUTGOING_CALLS = 54;
    public static final int OP_USE_FINGERPRINT = 55;
    public static final int OP_BODY_SENSORS = 56;
    public static final int OP_READ_CELL_BROADCASTS = 57;
    public static final int OP_MOCK_LOCATION = 58;
    public static final int OP_READ_EXTERNAL_STORAGE = 59;
    public static final int OP_WRITE_EXTERNAL_STORAGE = 60;
    public static final int OP_TURN_SCREEN_ON = 61;
    public static final int OP_GET_ACCOUNTS = 62;
    public static final int OP_RUN_IN_BACKGROUND = 63;
    public static final int OP_AUDIO_ACCESSIBILITY_VOLUME = 64;
    public static final int OP_READ_PHONE_NUMBERS = 65;
    public static final int OP_REQUEST_INSTALL_PACKAGES = 66;
    public static final int OP_PICTURE_IN_PICTURE = 67;
    public static final int OP_INSTANT_APP_START_FOREGROUND = 68;
    public static final int OP_ANSWER_PHONE_CALLS = 69;

    public static final int STATUS_SUCCESS = 0;
    public static final int STATUS_FAILURE = 1;

    public static final String USB_FUNCTION_NONE = "none";
    public static final String USB_FUNCTION_ADB = "adb";
    public static final String USB_FUNCTION_RNDIS = "rndis";
    public static final String USB_FUNCTION_MTP = "mtp";
    public static final String USB_FUNCTION_PTP = "ptp";

    public static final int ERROR_COMPONENT_STATE = -1;


    private static final int INSTALL_SUCCEEDED = 1;
    private static final int DELETE_SUCCEEDED = 1;

    private static final int INSTALL_REPLACE_EXISTING = 0x00000002;
    private static final int DELETE_SYSTEM_APP = 0x00000004;
    private static final int OP_MODE_INVALID = -1;

    private static final String ACTION_MASTER_CLEAR = "android.intent.action.MASTER_CLEAR";
    private static final String EXTRA_REASON = "android.intent.extra.REASON";
    private static final String EXTRA_WIPE_EXTERNAL_STORAGE = "android.intent.extra.WIPE_EXTERNAL_STORAGE";
    private static final String ACTION_FACTORY_RESET = "android.intent.action.FACTORY_RESET";  //8.0

    private static final int STATUS_BAR_DISABLE_EXPAND = 0x00010000;

    private Context mContext;

    private Handler mHandler;

    public SystemManager(Context context) {
        this.mContext = context;
    }

    /**
     * 允许运行时权限
     *
     * @param packageName
     * @param permissions
     * @return
     */
    public SystemManager allowPermission(String packageName, String... permissions) {
        if (permissions == null || permissions.length == 0) return this;
        if (!needRuntimePermission()) return this;
        for (String permission : permissions) {
            allowPermissionInner(packageName, permission);
        }
        return this;
    }

    public SystemManager allowPermission(String packageName, Collection<String> permissions) {
        if (permissions == null || permissions.isEmpty()) return this;
        String[] array = new String[permissions.size()];
        permissions.toArray(array);
        return allowPermission(packageName, array);
    }

    /**
     * 禁止运行时权限
     *
     * @param packageName
     * @param permissions
     * @return
     */
    public SystemManager denyPermission(String packageName, String... permissions) {
        if (permissions == null || permissions.length == 0) return this;
        if (!needRuntimePermission()) return this;
        for (String permission : permissions) {
            denyPermissionInner(packageName, permission);
        }
        return this;
    }

    public SystemManager denyPermission(String packageName, Collection<String> permissions) {
        if (permissions == null || permissions.isEmpty()) return this;
        String[] array = new String[permissions.size()];
        permissions.toArray(array);
        return denyPermission(packageName, array);
    }

    /**
     * 是否获取权限
     *
     * @param packageName
     * @param permissions
     * @return
     */
    public boolean isPermissionAllowed(String packageName, String... permissions) {
        if (permissions == null || permissions.length == 0) return true;
        if (!needRuntimePermission()) return true;
        Set<String> mDeniedPermissionList = getDeniedPermissionList(packageName, permissions);
        return mDeniedPermissionList.isEmpty();
    }


    /**
     * 设置OP模式
     *
     * @param packageName
     * @param opCode
     * @param mode
     * @return
     */
    public SystemManager setOpMode(String packageName, int opCode, int mode) {
        try {
            Method method = AppOpsManager.class.getMethod("setMode", int.class, int.class, String.class, int.class);
            AppOpsManager mAppOps = (AppOpsManager) mContext.getSystemService(Service.APP_OPS_SERVICE);
            method.invoke(mAppOps, opCode, getPackageUid(packageName), packageName, mode);
        } catch (Exception e) {
            printError(e);
        }
        return this;
    }

    /**
     * 允许OP权限
     *
     * @param packageName
     * @param opCode
     * @return
     */
    public SystemManager allowOp(String packageName, int opCode) {
        setOpMode(packageName, opCode, AppOpsManager.MODE_ALLOWED);
        return this;
    }

    /**
     * 禁止OP权限
     *
     * @param packageName
     * @param opCode
     * @return
     */
    public SystemManager denyOp(String packageName, int opCode) {
        setOpMode(packageName, opCode, AppOpsManager.MODE_IGNORED);
        return this;
    }

    /**
     * 是否允许OP
     *
     * @param packageName
     * @param opCode
     * @return
     */
    public boolean isOpAllowed(String packageName, int opCode) {
        return getOpMode(packageName, opCode) == AppOpsManager.MODE_ALLOWED;
    }

    /**
     * 获取OP模式
     *
     * @param packageName
     * @param opCode
     * @return
     */
    public int getOpMode(String packageName, int opCode) {
        try {
            Object object = mContext.getSystemService(Context.APP_OPS_SERVICE);
            if (object == null) {
                return AppOpsManager.MODE_ALLOWED;
            }
            Class localClass = object.getClass();
            Class[] arrayOfClass = new Class[3];
            arrayOfClass[0] = Integer.TYPE;
            arrayOfClass[1] = Integer.TYPE;
            arrayOfClass[2] = String.class;
            Method method = localClass.getMethod("checkOpNoThrow", arrayOfClass);

            if (method == null) {
                return OP_MODE_INVALID;
            }
            Object[] arrayOfObject = new Object[3];
            arrayOfObject[0] = Integer.valueOf(opCode);
            arrayOfObject[1] = Integer.valueOf(getPackageUid(packageName));
            arrayOfObject[2] = packageName;
            int m = ((Integer) method.invoke(object, arrayOfObject)).intValue();
            print("m=" + m);
            return m;
        } catch (Exception e) {
            e.printStackTrace();
            printError(e);
        }
        return OP_MODE_INVALID;
    }

    /**
     * 允许禁止悬浮窗权限
     *
     * @param packageName
     * @return
     */
    public SystemManager allowDrawOverlays(String packageName, boolean isAllow) {
        if (needRuntimePermission()) {
            setOpState(packageName, OP_SYSTEM_ALERT_WINDOW, isAllow);
        }
        return this;
    }

    /**
     * 是否允许悬浮窗
     *
     * @param packageName
     * @return
     */
    public boolean isDrawOverlaysAllowed(String packageName) {
        return isOpAllowed(packageName, OP_SYSTEM_ALERT_WINDOW);
    }

    /**
     * 允许禁止修改设置权限
     *
     * @param packageName
     * @return
     */
    public SystemManager allowWriteSettings(String packageName, boolean isAllow) {
        if (needRuntimePermission()) {
            setOpState(packageName, OP_WRITE_SETTINGS, isAllow);
        }
        return this;
    }

    /**
     * 是否允许修改设置
     *
     * @param packageName
     * @return
     */
    public boolean isWriteSettingsAllowed(String packageName) {
        return isOpAllowed(packageName, OP_WRITE_SETTINGS);
    }

    /**
     * 允许禁止查看应用统计
     *
     * @param packageName
     * @return
     */
    public SystemManager allowUsageStats(String packageName, boolean isAllow) {
        setOpState(packageName, OP_GET_USAGE_STATS, isAllow);
        return this;
    }

    /**
     * 是否允许查看应用统计
     *
     * @param packageName
     * @return
     */
    public boolean isUsageStatsAllowed(String packageName) {
        return isOpAllowed(packageName, OP_GET_USAGE_STATS);
    }

    /**
     * 允许禁止投屏
     *
     * @param packageName
     * @return
     */
    public SystemManager allowProjectMedia(String packageName, boolean isAllow) {
        setOpState(packageName, OP_PROJECT_MEDIA, isAllow);
        return this;
    }

    /**
     * 是否允许投屏
     *
     * @param packageName
     * @return
     */
    public boolean isProjectMediaAllowed(String packageName) {
        return isOpAllowed(packageName, OP_PROJECT_MEDIA);
    }


    /**
     * 允许禁止无障碍
     *
     * @param packageName
     * @param className
     * @param allow
     * @return
     */
    public SystemManager allowAccessibility(String packageName, String className, boolean allow) {
        if (!isSupportAccessibility()) return this;
        boolean hasService = isAccessibilityServiceEnabled(packageName, className);
        String srcServiceName = Settings.Secure.getString(mContext.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
        String myServiceName = packageName + "/" + className;
        if (allow) {
            if (!hasService) {
                int enabled = 0;
                try {
                    enabled = Settings.Secure.getInt(mContext.getContentResolver(), Settings.Secure.ACCESSIBILITY_ENABLED);
                } catch (Settings.SettingNotFoundException e) {
                    e.printStackTrace();
                }
                if (enabled == 0) {
                    try {
                        Settings.Secure.putInt(mContext.getContentResolver(), Settings.Secure.ACCESSIBILITY_ENABLED, 1);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                if (srcServiceName == null || srcServiceName.trim().isEmpty()) {
                    srcServiceName = myServiceName;
                } else {
                    srcServiceName = srcServiceName + ":" + myServiceName;
                }
                try {
                    Settings.Secure.putString(mContext.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, makeSettingsValue(srcServiceName));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } else {
            if (hasService) {
                if (srcServiceName.equals(myServiceName)) {
                    srcServiceName = "";
                } else {
                    if (srcServiceName.endsWith(myServiceName)) {
                        srcServiceName = srcServiceName.replace(":" + myServiceName, "");
                    } else {
                        srcServiceName = srcServiceName.replace(myServiceName + ":", "");
                    }
                }
                if (srcServiceName.isEmpty()) {
                    srcServiceName = "\"\"";
                }
                try {
                    Settings.Secure.putString(mContext.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, makeSettingsValue(srcServiceName));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return this;
    }

    /**
     * 允许禁止无障碍
     *
     * @param service
     * @param allow
     * @return
     */
    public SystemManager allowAccessibility(Class<? extends AccessibilityService> service, boolean allow) {
        allowAccessibility(mContext.getPackageName(), service.getName(), allow);
        return this;
    }

    /**
     * 允许禁止无障碍
     *
     * @param service
     * @param allow
     * @return
     */
    public SystemManager allowAccessibility(ComponentName service, boolean allow) {
        allowAccessibility(service.getPackageName(), service.getClassName(), allow);
        return this;
    }

    /**
     * 允许禁止设备管理器
     *
     * @param packageName
     * @param className
     * @param allow
     * @return
     */
    public SystemManager allowDeviceAdmin(String packageName, String className, boolean allow) {
        allowDeviceAdmin(new ComponentName(packageName, className), allow);
        return this;
    }

    /**
     * 允许禁止设备管理器
     *
     * @param activeAdmin
     * @param allow
     * @return
     */
    public SystemManager allowDeviceAdmin(Class<? extends DeviceAdminReceiver> activeAdmin, boolean allow) {
        allowDeviceAdmin(new ComponentName(mContext, activeAdmin), allow);
        return this;
    }

    /**
     * 允许禁止设备管理器
     *
     * @param activeAdmin
     * @param allow
     * @return
     */
    public SystemManager allowDeviceAdmin(ComponentName activeAdmin, boolean allow) {
        if (!isSupportDeviceAdmin()) return this;
        if (allow) {
            try {
                Method method = DevicePolicyManager.class.getMethod("setActiveAdmin", ComponentName.class, boolean.class);
                DevicePolicyManager dpm = (DevicePolicyManager) mContext.getSystemService(Service.DEVICE_POLICY_SERVICE);
                method.invoke(dpm, activeAdmin, true);
            } catch (Exception e) {
                printError(e);
            }
        } else {
            try {
                DevicePolicyManager dpm = (DevicePolicyManager) mContext.getSystemService(Service.DEVICE_POLICY_SERVICE);
                dpm.removeActiveAdmin(activeAdmin);
            } catch (Exception e) {
                printError(e);
            }
        }
        return this;
    }


    /**
     * 是否支持设备管理器
     *
     * @return
     */
    public static boolean isSupportDeviceAdmin() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.FROYO;
    }

    /**
     * 是否支持无障碍
     *
     * @return
     */
    public static boolean isSupportAccessibility() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.DONUT;
    }

    /**
     * 是否需要请求权限
     *
     * @return
     */
    public static boolean needRuntimePermission() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }

    /**
     * 是否启用无障碍
     *
     * @param pkgName
     * @param className
     * @return
     */
    public boolean isAccessibilityServiceEnabled(String pkgName, String className) {
        if (!isSupportAccessibility()) {
            return false;
        }
        if (isEmpty(pkgName) || isEmpty(className)) {
            return false;
        }
        try {
            int enabled = Settings.Secure.getInt(mContext.getContentResolver(), Settings.Secure.ACCESSIBILITY_ENABLED);
            if (enabled == 1) {
                String service = Settings.Secure.getString(mContext.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
                if (className.startsWith(".")) {
                    className = pkgName + className;
                }
                String myServiceName = pkgName + "/" + className;

                boolean hasService = service != null && service.contains(myServiceName);
                return hasService;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 是否启用无障碍
     *
     * @param serviceClass
     * @return
     */
    public boolean isAccessibilityServiceEnabled(Class<? extends AccessibilityService> serviceClass) {
        return isAccessibilityServiceEnabled(mContext.getPackageName(), serviceClass.getCanonicalName());
    }

    /**
     * 是否启用无障碍
     *
     * @param service
     * @return
     */
    public boolean isAccessibilityServiceEnabled(ComponentName service) {
        return isAccessibilityServiceEnabled(service.getPackageName(), service.getClassName());
    }

    /**
     * 是否是设备管理器
     *
     * @param admin
     * @return
     */
    public boolean isDeviceAdmin(ComponentName admin) {
        if (!isSupportDeviceAdmin()) {
            return false;
        }
        DevicePolicyManager dpm = (DevicePolicyManager) mContext.getSystemService(Service.DEVICE_POLICY_SERVICE);
        return dpm.isAdminActive(admin);
    }

    /**
     * 是否是设备管理器
     *
     * @param pkgName
     * @param className
     * @return
     */
    public boolean isDeviceAdmin(String pkgName, String className) {
        return isDeviceAdmin(new ComponentName(pkgName, className));
    }

    /**
     * 是否是设备管理器
     *
     * @param receiverClass
     * @return
     */
    public boolean isDeviceAdmin(Class<? extends DeviceAdminReceiver> receiverClass) {
        return isDeviceAdmin(new ComponentName(mContext, receiverClass));
    }

    /**
     * 设置设备所有者
     *
     * @param pkgName
     * @return
     */
    public boolean setDeviceOwner(String pkgName) {
        if (!isSupportDeviceAdmin()) {
            return false;
        }
        ComponentName admin = getDeviceAdminClass(mContext, pkgName);
        if (admin == null) {
            return false;
        }
        DevicePolicyManager dpm = (DevicePolicyManager) mContext.getSystemService(Service.DEVICE_POLICY_SERVICE);
        try {
            Method method = dpm.getClass().getMethod("setDeviceOwner", ComponentName.class);
            return (boolean) method.invoke(dpm, admin);
        } catch (Exception e) {
            printError(e);
        }
        return false;
    }

    /**
     * 移除设备所有者
     *
     * @param pkgName
     */
    public void removeDeviceOwner(String pkgName) {
        DevicePolicyManager dpm = (DevicePolicyManager) mContext.getSystemService(Service.DEVICE_POLICY_SERVICE);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                dpm.clearDeviceOwnerApp(pkgName);
            }
        } catch (Exception e) {
            printError(e);
        }
    }


    /**
     * 是否设备所有者
     *
     * @param pkgName
     * @return
     */
    public boolean isDeviceOwner(String pkgName) {
        if (!isSupportDeviceAdmin()) {
            return false;
        }
        DevicePolicyManager dpm = (DevicePolicyManager) mContext.getSystemService(Service.DEVICE_POLICY_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            return dpm.isDeviceOwnerApp(pkgName);
        }
        return false;
    }

    /**
     * 设置包状态
     *
     * @param packageName
     * @param state       PackageManager.COMPONENT_
     */
    public boolean setPackageState(String packageName, int state) {
        try {
            mContext.getPackageManager().setApplicationEnabledSetting(packageName, state, 0);
            return true;
        } catch (Exception e) {
            printError(e);
        }
        return false;
    }

    /**
     * 获取包状态
     *
     * @param packageName
     * @return
     */
    public int getPackageState(String packageName) {
        try {
            return mContext.getPackageManager().getApplicationEnabledSetting(packageName);
        } catch (Exception e) {
            printError(e);
        }
        return ERROR_COMPONENT_STATE;
    }

    /**
     * 设置组件状态
     *
     * @param componentName
     * @param state:PackageManager.COMPONENT_
     */
    public boolean setComponentState(ComponentName componentName, int state) {
        try {
            mContext.getPackageManager().setComponentEnabledSetting(componentName, state, 0);
            return true;
        } catch (Exception e) {
            printError(e);
        }
        return false;
    }

    /**
     * 获取组件状态
     *
     * @param componentName
     * @return
     */
    public int getComponentState(ComponentName componentName) {
        try {
            return mContext.getPackageManager().getComponentEnabledSetting(componentName);
        } catch (Exception e) {
            printError(e);
        }
        return ERROR_COMPONENT_STATE;
    }

    /**
     * 设置组件状态
     *
     * @param packageName
     * @param className
     * @param state:PackageManager.COMPONENT_
     */
    public boolean setComponentState(String packageName, String className, int state) {
        return setComponentState(new ComponentName(packageName, className), state);
    }

    /**
     * 禁止包
     *
     * @param packageName
     * @param disable
     */
    public boolean disablePackage(String packageName, boolean disable) {
        return setPackageState(packageName, disable ? PackageManager.COMPONENT_ENABLED_STATE_DISABLED : PackageManager.COMPONENT_ENABLED_STATE_ENABLED);
    }

    /**
     * 判断包是否禁止
     *
     * @param packageName
     * @return
     */
    public boolean isPackageDisabled(String packageName) {
        int state = getPackageState(packageName);
        return state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                || state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER;
    }

    /**
     * 禁止组件
     *
     * @param componentName
     * @param disable
     */
    public boolean disableComponent(ComponentName componentName, boolean disable) {
        return setComponentState(componentName, disable ? PackageManager.COMPONENT_ENABLED_STATE_DISABLED : PackageManager.COMPONENT_ENABLED_STATE_ENABLED);
    }

    /**
     * 禁止组件
     *
     * @param packageName
     * @param className
     * @param disable
     */
    public boolean disableComponent(String packageName, String className, boolean disable) {
        return disableComponent(new ComponentName(packageName, className), disable);
    }

    /**
     * 判断组件是否禁止
     *
     * @param componentName
     * @return
     */
    public boolean isComponentDisabled(ComponentName componentName) {
        int state = getComponentState(componentName);
        return state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                || state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER;
    }

    /**
     * 判断组件是否禁止
     *
     * @param packageName
     * @param className
     * @return
     */
    public boolean isComponentDisabled(String packageName, String className) {
        return isComponentDisabled(new ComponentName(packageName, className));
    }

    /**
     * 杀死应用
     *
     * @param packageName
     */
    public void killApplication(String packageName) {
        try {
            Method method = ActivityManager.class.getMethod("forceStopPackage", String.class);
            ActivityManager am = (ActivityManager) mContext.getSystemService(Service.ACTIVITY_SERVICE);
            method.invoke(am, packageName);
        } catch (Exception e) {
            printError(e);
        }
    }

    /**
     * 清除应用数据
     *
     * @param packageName
     * @return
     */
    public boolean clearApplicationData(String packageName) {
        boolean isSuccess = false;
        IPackageDataObserver.Stub mStub = new IPackageDataObserver.Stub() {
            public void onRemoveCompleted(String paramAnonymousString, boolean paramAnonymousBoolean) {
            }
        };
        try {
            Method method = ActivityManager.class.getMethod("clearApplicationUserData", String.class, IPackageDataObserver.class);
            ActivityManager am = (ActivityManager) mContext.getSystemService(Service.ACTIVITY_SERVICE);
            isSuccess = (boolean) method.invoke(am, packageName, mStub);
        } catch (Exception e) {
            printError(e);
        }
        return isSuccess;
    }

    /**
     * 清除应用缓存
     *
     * @param packageName
     */
    public void clearApplicationCache(String packageName) {
        IPackageDataObserver.Stub mStub = new IPackageDataObserver.Stub() {
            public void onRemoveCompleted(String paramAnonymousString, boolean paramAnonymousBoolean) {
            }
        };
        try {
            Method method = PackageManager.class.getMethod("deleteApplicationCacheFiles", String.class, IPackageDataObserver.class);
            PackageManager pm = mContext.getPackageManager();
            method.invoke(pm, packageName, mStub);
        } catch (Exception e) {
            printError(e);
        }
    }

    /**
     * 安装应用
     *
     * @param path
     */
    public void installPackage(final String path, final OnPackageInstallListener listener) {
        if (Build.VERSION.SDK_INT < 28) {
            IPackageInstallObserver.Stub mStub = new IPackageInstallObserver.Stub() {
                @Override
                public void packageInstalled(String packageName, int returnCode) throws RemoteException {
                    if (listener != null)
                        listener.onPackageInstalled(packageName, returnCode == INSTALL_SUCCEEDED ? STATUS_SUCCESS : STATUS_FAILURE);
                }
            };
            try {
                Method method = PackageManager.class.getMethod("installPackage", Uri.class, IPackageInstallObserver.class, int.class, String.class);
                PackageManager pm = mContext.getPackageManager();
                Uri uri = Uri.fromFile(new File(path));
                method.invoke(pm, uri, mStub, INSTALL_REPLACE_EXISTING, null);
            } catch (Exception e) {
                printError(e);
            }
        } else {
            installPackageFromQ(path, listener);
        }

    }


    /**
     * 安装应用
     *
     * @param path
     */
    public void installPackage(String path) {
        installPackage(path, null);
    }

    public boolean launchApplication(String packageName) {
        try {
            Intent intent = mContext.getPackageManager().getLaunchIntentForPackage(packageName);
            if (intent != null) {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                mContext.startActivity(intent);
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 卸载应用
     *
     * @param packageName
     */
    public void deletePackage(String packageName, final OnPackageDeleteListener listener) {
        IPackageDeleteObserver.Stub mStub = new IPackageDeleteObserver.Stub() {
            @Override
            public void packageDeleted(String packageName, int returnCode) throws RemoteException {
                if (listener != null) {
                    listener.onPackageDeleted(packageName, returnCode == DELETE_SUCCEEDED ? STATUS_SUCCESS : STATUS_FAILURE);
                }
            }
        };
        try {
            Method method = PackageManager.class.getMethod("deletePackage", String.class, IPackageDeleteObserver.class, int.class);
            PackageManager pm = mContext.getPackageManager();
            method.invoke(pm, packageName, mStub, DELETE_SYSTEM_APP);
        } catch (Exception e) {
            printError(e);
        }
    }

    /**
     * 卸载应用
     *
     * @param packageName
     */
    public void deletePackage(String packageName) {
        deletePackage(packageName, null);
    }

    /**
     * 重启
     */
    public void reboot() {
        PowerManager pm = (PowerManager) mContext.getSystemService(Service.POWER_SERVICE);
        pm.reboot("");
    }

    /**
     * 关机
     */
    public void shutdown() {
        try {
            Method method = PowerManager.class.getMethod("shutdown", boolean.class, String.class, boolean.class);
            PowerManager pm = (PowerManager) mContext.getSystemService(Service.POWER_SERVICE);
            method.invoke(pm, false, "", false);
        } catch (Exception e) {
            printError(e);
        }
    }

    /**
     * 恢复出厂设置
     */
    public void wipeData() {
        if (Build.VERSION.SDK_INT >= 26) {
            //8.0以上
            Intent intent = new Intent(ACTION_FACTORY_RESET);
            intent.setPackage("android");
            intent.addFlags(Intent.FLAG_RECEIVER_FOREGROUND);
            intent.putExtra(EXTRA_REASON, "MasterClearConfirm");
            intent.putExtra(EXTRA_WIPE_EXTERNAL_STORAGE, true);
            mContext.sendBroadcast(intent);
        } else {
            Intent intent = new Intent(ACTION_MASTER_CLEAR);
            intent.addFlags(Intent.FLAG_RECEIVER_FOREGROUND);
            intent.putExtra(EXTRA_REASON, "MasterClearConfirm");
            intent.putExtra(EXTRA_WIPE_EXTERNAL_STORAGE, true);
            mContext.sendBroadcast(intent);
        }
    }

    /**
     * 设置系统时间
     *
     * @param time
     */
    public void setSystemTime(long time) {
        AlarmManager am = (AlarmManager) mContext.getSystemService(Service.ALARM_SERVICE);
        am.setTime(time);
        //SystemClock.setCurrentTimeMillis(time);
    }

    /**
     * 执行shell命令
     * @param command
     */
    public void execSync(String command) {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(command);
            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (process != null) {
                    process.destroy();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 执行shell命令
     * @param command
     */
    public void exec(final String command) {
        new Thread() {
            @Override
            public void run() {
                super.run();
                execSync(command);
            }
        }.start();
    }

    /**
     * 设置主线程处理
     *
     * @param mHandler
     */
    public void setUiHandler(Handler mHandler) {
        this.mHandler = mHandler;
    }

    /**
     * 禁止状态栏展开
     *
     * @param disable
     */
    public void disableStatusBarExpand(boolean disable) {
        try {
            Object service = mContext.getSystemService("statusbar");
            Class<?> c = Class.forName("android.app.StatusBarManager");
            Method method = c.getMethod("disable", int.class);
            method.invoke(service, disable ? STATUS_BAR_DISABLE_EXPAND : 0);
        } catch (Exception e) {
            printError(e);
        }
    }

    /**
     * 设置usb功能
     *
     * @param function
     */
    public void setUsbFunction(String function) {
        UsbManager um = (UsbManager) mContext.getSystemService(Service.USB_SERVICE);
        if (Build.VERSION.SDK_INT < 26) {
            //8.0以下
            try {
                Method setCurrentFunction = um.getClass().getMethod("setCurrentFunction", String.class);
                setCurrentFunction.invoke(um, function);

                Method setUsbDataUnlocked = um.getClass().getMethod("setUsbDataUnlocked", boolean.class);
                if (function != null && function.equals("none")) {
                    setUsbDataUnlocked.invoke(um, false);
                } else {
                    setUsbDataUnlocked.invoke(um, true);
                }
            } catch (Exception e) {
                printError(e);
            }
        } else {
            //8.0以上
            try {
                Method setCurrentFunction = um.getClass().getMethod("setCurrentFunction", String.class, boolean.class);
                if (function != null && function.equals("none")) {
                    setCurrentFunction.invoke(um, function, false);
                } else {
                    setCurrentFunction.invoke(um, function, true);
                }
            } catch (Exception e) {
                printError(e);
            }
        }

    }

    /**
     * 设置用户限制
     *
     * @param key
     * @param value
     */
    public void setUserRestriction(String key, boolean value) {
        UserManager um = (UserManager) mContext.getSystemService(Service.USER_SERVICE);
        try {
            Method method = um.getClass().getMethod("setUserRestriction", String.class, boolean.class);
            method.invoke(um, key, value);
        } catch (Exception e) {
            printError(e);
        }
    }

    /**
     * 是否有用户限制
     *
     * @param key
     * @return
     */
    public boolean hasUserRestriction(String key) {
        UserManager um = (UserManager) mContext.getSystemService(Service.USER_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return um.hasUserRestriction(key);
        }
        return false;
    }

    /*
     * 内部数据
     *
     */
    private static boolean hasElement(Collection c) {
        return c != null && !c.isEmpty();
    }

    private static boolean hasElement(Object[] array) {
        return array != null && array.length > 0;
    }

    private static boolean hasElement(Map map) {
        return map != null && !map.isEmpty();
    }

    private static boolean hasValue(String value) {
        return value != null && !value.isEmpty();
    }

    private static boolean isEmpty(String value) {
        return !hasValue(value);
    }

    private static boolean isNumeric(String str) {
        Pattern pattern = Pattern.compile("[0-9]*");
        return pattern.matcher(str).matches();
    }

    private static boolean equalsValue(String v1, String v2) {
        return v1 != null && v2 != null && v1.equals(v2);
    }

    private SystemManager setOpState(String packageName, int opCode, boolean isAllow) {
        if (isAllow) {
            setOpMode(packageName, opCode, AppOpsManager.MODE_ALLOWED);
        } else {
            setOpMode(packageName, opCode, AppOpsManager.MODE_IGNORED);
        }
        return this;
    }

    private void allowPermissionInner(String packageName, String permission) {
        try {
            Method method = PackageManager.class.getMethod("grantRuntimePermission", String.class, String.class, UserHandle.class);
            UserHandle userHandle = (UserHandle) newInstance(UserHandle.class, new Class[]{int.class}, 0);
            method.invoke(mContext.getPackageManager(), packageName, permission, userHandle);
        } catch (Exception e) {
            printError(e);
        }
    }

    private void denyPermissionInner(String packageName, String permission) {
        try {
            Method method = PackageManager.class.getMethod("revokeRuntimePermission", String.class, String.class, UserHandle.class);
            UserHandle userHandle = (UserHandle) newInstance(UserHandle.class, new Class[]{int.class}, 0);
            method.invoke(mContext.getPackageManager(), packageName, permission, userHandle);
        } catch (Exception e) {
            printError(e);
        }
    }

    private int getPackageUid(String packageName) {
        try {
            PackageInfo info = mContext.getPackageManager().getPackageInfo(packageName, 0);
            if (info != null && info.applicationInfo != null) {
                return info.applicationInfo.uid;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }

    private String makeSettingsValue(String value) {
        return value != null && !value.trim().isEmpty() ? value : "\"\"";
    }

    public interface OnPackageInstallListener {
        void onPackageInstalled(String packageName, int returnCode);
    }

    public interface OnPackageDeleteListener {
        void onPackageDeleted(String packageName, int returnCode);
    }

    private Set<String> getDeniedPermissionList(String packageName, String[] permissions) {
        Set<String> mDeniedPermissionList = new HashSet<>();
        PackageManager pm = mContext.getPackageManager();
        for (String permission : permissions) {
            if (pm.checkPermission(permission, packageName) != PackageManager.PERMISSION_GRANTED) {
                mDeniedPermissionList.add(permission);
            }
        }
        return mDeniedPermissionList;
    }

    private Object newInstance(Class clazz, Class[] argsType, Object... args) {
        Object instance = null;
        try {
            Constructor constructor = clazz.getConstructor(argsType);
            constructor.setAccessible(true);
            instance = constructor.newInstance(args);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return instance;
    }

    private void print(Object... info) {
        if (info == null || info.length == 0) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (Object o : info) {
            sb.append(o != null ? o.toString() + ", " : ", ");
        }
        String msg = sb.toString();
        if (msg.endsWith(",")) msg = sb.deleteCharAt(sb.length() - 1).toString();
        Log.e(TAG, msg);
    }

    private void printError(Throwable e) {
        if (e.getCause() != null) {
            Log.e(TAG, e.getCause().toString());
        } else {
            Log.e(TAG, e.toString());
        }
    }



    /**
     * android9.0 安装应用
     *
     * @param path
     * @param listener
     */
    private void installPackageFromQ(final String path, final OnPackageInstallListener listener) {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return;
        }

        PackageManager pm = mContext.getPackageManager();
        String packageName = null;

        PackageInfo packageInfo = pm.getPackageArchiveInfo(path, PackageManager.GET_ACTIVITIES | PackageManager.GET_SERVICES);
        if (packageInfo != null) {
            packageName = packageInfo.packageName;
        }

        PackageInstaller packageInstaller = pm.getPackageInstaller();
        PackageInstaller.SessionParams sessionParams = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);

        File apkFile = new File(path);
        print("apkFile length" + apkFile.length());
        sessionParams.setSize(apkFile.length());

        int mSessionId = -1;
        try {
            mSessionId = packageInstaller.createSession(sessionParams);
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (mSessionId != -1) {
            final int finalMSessionId = mSessionId;
            final String finalPackageName = packageName;
            new Thread() {
                @Override
                public void run() {
                    super.run();
                    boolean copySuccess = onTransfesApkFile(path, finalMSessionId);
                    if (copySuccess) {
                        if (mHandler != null) {
                            mHandler.post(new Runnable() {
                                @Override
                                public void run() {
                                    execInstallAPP(finalMSessionId, finalPackageName, listener);
                                }
                            });
                        } else {
                            execInstallAPP(finalMSessionId, finalPackageName, listener);
                        }
                    } else {
                        if (mHandler != null) {
                            mHandler.post(new Runnable() {
                                @Override
                                public void run() {
                                    if (listener != null) {
                                        listener.onPackageInstalled(finalPackageName, STATUS_FAILURE);
                                    }
                                }
                            });
                        } else {
                            if (listener != null) {
                                listener.onPackageInstalled(finalPackageName, STATUS_FAILURE);
                            }
                        }
                    }
                }
            }.start();
        } else {
            if (listener != null) {
                listener.onPackageInstalled(packageName, STATUS_FAILURE);
            }
        }

    }





    private boolean onTransfesApkFile(String apkFilePath, int mSessionId) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            InputStream in = null;
            OutputStream out = null;
            PackageInstaller.Session session = null;
            boolean success = false;
            try {
                File apkFile = new File(apkFilePath);
                session = mContext.getPackageManager().getPackageInstaller().openSession(mSessionId);
                out = session.openWrite("base.apk", 0, apkFile.length());
                in = new FileInputStream(apkFile);
                int total = 0, c;
                byte[] buffer = new byte[1024 * 1024];
                while ((c = in.read(buffer)) != -1) {
                    total += c;
                    out.write(buffer, 0, c);
                }
                session.fsync(out);
                success = true;
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (null != session) {
                    session.close();
                }
                try {
                    if (null != out) {
                        out.close();
                    }
                    if (null != in) {
                        in.close();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            return success;
        }
        return false;
    }

    /**
     * 执行安装并通知安装结果
     */
    private void execInstallAPP(int mSessionId, final String packageName, final OnPackageInstallListener listener) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            PackageInstaller.Session session = null;
            try {
                session = mContext.getPackageManager().getPackageInstaller().openSession(mSessionId);
                Intent intent = new Intent(mContext, new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context context, Intent intent) {
                        if (intent != null) {
                            int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
                            if (listener != null) {
                                listener.onPackageInstalled(packageName, status);
                            }
                        }
                    }
                }.getClass());
                PendingIntent pendingIntent = PendingIntent.getBroadcast(mContext,
                        1, intent,
                        PendingIntent.FLAG_UPDATE_CURRENT);
                session.commit(pendingIntent.getIntentSender());
            } catch (Exception e) {
                e.printStackTrace();
                if (listener != null) {
                    listener.onPackageInstalled(packageName, STATUS_FAILURE);
                }
            } finally {
                if (null != session) {
                    session.close();
                }
            }
        }
    }

    private ComponentName getDeviceAdminClass(Context context, String pkgName) {
        List<ResolveInfo> infos = context.getPackageManager().queryBroadcastReceivers(
                new Intent(DeviceAdminReceiver.ACTION_DEVICE_ADMIN_ENABLED),
                PackageManager.GET_DISABLED_UNTIL_USED_COMPONENTS);
        if (infos != null) {
            for (ResolveInfo info : infos) {
                if (info.activityInfo.packageName.equals(pkgName)) {
                    return new ComponentName(pkgName, info.activityInfo.name);
                }
            }
        }
        return null;
    }

    private boolean isAppInstalled(String pkgName) {
        try {
            PackageInfo info = mContext.getPackageManager().getPackageInfo(pkgName, 0);
            return info != null;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

}
