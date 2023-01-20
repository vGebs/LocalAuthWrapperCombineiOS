import Combine
import LocalAuthentication

public enum BiometryType {
    case faceID
    case touchID
    case passphrase
}

public enum LocalAuthError: Error {
    case biometryNotAvailable
}

@available(iOS 13.0, *)
public class LocalAuthCombine {
    
    private var context: LAContext
    private var biometryType: BiometryType?
    
    public init(context: LAContext) {
        self.context = context
        checkSupport()
    }

    public func authenticateUser(reason: String) -> AnyPublisher<Bool, Error> {
        if biometryType == .faceID || biometryType == .touchID {
            return authenticateWithBiometry(reason: reason)
        } else if biometryType == .passphrase {
            return authenticateWithPassphrase(reason: reason)
        } else {
            return Fail(error: LocalAuthError.biometryNotAvailable)
                .eraseToAnyPublisher()
        }
    }

    public func invalidateSession(newContext: LAContext) {
        context.invalidate()
        self.context = newContext
    }
    
    public func checkBiometryStatus() -> (Bool, BiometryType?) {
        return (biometryType != nil, biometryType)
    }

    private func authenticateWithBiometry(reason: String) -> AnyPublisher<Bool, Error> {
        Future<Bool, Error> { [weak self] promise in
            self?.context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            ) { (success, error) in
                if let error = error {
                    promise(.failure(error))
                } else {
                    promise(.success(success))
                }
            }
        }
        .eraseToAnyPublisher()
    }

    private func authenticateWithPassphrase(reason: String) -> AnyPublisher<Bool, Error> {
        Future<Bool, Error> { [weak self] promise in
            self?.context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            ) { (success, error) in
                if let error = error {
                    promise(.failure(error))
                } else {
                    promise(.success(success))
                }
            }
        }
        .eraseToAnyPublisher()
    }
    
    private func checkSupport(){
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            switch context.biometryType {
            case .faceID:
                biometryType = .faceID
            case .touchID:
                biometryType = .touchID
            default:
                biometryType = nil
            }
        } else if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            biometryType = .passphrase
        } else {
            biometryType = nil
        }
    }
}
