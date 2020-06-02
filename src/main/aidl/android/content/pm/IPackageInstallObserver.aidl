// IPackageInstallObserver.aidl
package android.content.pm;

// Declare any non-default types here with import statements

interface IPackageInstallObserver {
    void packageInstalled(in String packageName, int returnCode);
}
