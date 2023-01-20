# LocalAuthWrapperCombineiOS

A simple and easy-to-use interface for Local Authentication using Face ID, Touch ID, or Passphrase and is compatible with Combine Swift.

## Features

Authenticate users with:

- FaceID
- TouchID
- Passphrase

## Installation

### Swift Package Manager

You can install `LocalAuthWrapperCombineiOS` using the [Swift Package Manager](https://swift.org/package-manager/).

1. In Xcode, open your project and navigate to File > Swift Packages > Add Package Dependency.
2. Enter the repository URL `https://github.com/vGebs/LocalAuthWrapperCombineiOS.git` and click Next.
3. Select the version you want to install, or leave the default version and click Next.
4. In the "Add to Target" section, select the target(s) you want to use `LocalAuthWrapperCombineiOS` in and click Finish.

## Usage

### Face ID Usage Description

Make sure to add a usage description for `Privacy - Face ID Usage Description` 

### Initialization

To use the `LocalAuthCombine` class, you need to create an instance of LAContext and pass it to the LocalAuth class.

```swift
let context = LAContext()
let localAuth = LocalAuthCombine(context: context)
```

You can further tune the LAContext() object if necessary.

## Authenticating a user

You can authenticate a user using Face ID, Touch ID, or Passphrase by calling the authenticateUser(reason:completion:) function. 

```swift
localAuth.authenticateUser(reason: "Please login to continue")
    .sink { completion in
        switch completion {
        case .finished:
            print("Logged in")
        case .failure(let err):
            switch err {
            case LAError.userCancel:
                print("Authentication was cancelled by user.")
            case LAError.authenticationFailed:
                print("Authentication failed.")
            case LAError.passcodeNotSet:
                print("A passcode has not been set.")
            case LAError.systemCancel:
                print("Authentication was cancelled by the system.")
            case LAError.biometryNotAvailable:
                print("Biometry is not available.")
            case LAError.biometryNotEnrolled:
                print("Biometry has no enrolled identities.")
            default:
                print("Authentication failed with error: \(err)")
            }
        }
    } receiveValue: { [weak self] _ in }
    .store(in: &cancellables)
```

## Invalidating session

You can invalidate the current session by calling the invalidateSession(newContext:) function. When invalidating the session, the current LAContext object is destroyed, so make sure to pass in a newly defined context.

Invalidating the session can be used when a user logs out of the application. This function must be called when logging out, or else the user will not be prompted with biometry when they try to re-enter.

```swift
let newContext = LAContext()
localAuth.invalidateSession(newContext: newContext)
```

## Checking Biometry Status

You can check if the device has biometry capability and what type of biometry it is by calling the checkBiometryStatus() function.

```swift
let (isBiometryAvailable, biometryType) = auth.checkBiometryStatus()
if isBiometryAvailable {
    print("Biometry available: \(biometryType!)")
} else {
    print("Biometry not available")
}
```

## Conclusion

This interface makes it easy to implement Local Authentication in your iOS app using Face ID, Touch ID, or Passphrase. It also provides a simple and convenient way to check the biometry status of the device and invalidate the current session.

It's important to keep in mind that this interface is a basic implementation and it's recommended to use it in conjunction with other security measures to protect the user's data.

## License

`LocalAuthWrapperCombineiOS` is released under the MIT license. See LICENSE for details.

## Contribution

We welcome contributions to `LocalAuthWrapperCombineiOS`. If you have a bug fix or a new feature, please open a pull request.

