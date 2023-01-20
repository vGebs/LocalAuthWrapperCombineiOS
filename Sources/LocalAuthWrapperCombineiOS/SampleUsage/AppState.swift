//
//  File.swift
//  
//
//  Created by Vaughn on 2023-01-19.
//


import Combine
import LocalAuthentication

@available(iOS 13.0, *)
class AppState: ObservableObject {
    
    static let shared = AppState()
    
    var localAuth: LocalAuthCombine
    
    @Published var allowAccess = false
    
    private var cancellables: [AnyCancellable] = []
    
    private init() {
        let context = LAContext()
        self.localAuth = LocalAuthCombine(context: context)
    }
    
    func login() {
        
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
            } receiveValue: { [weak self] _ in
                self?.allowAccess = true
            }
            .store(in: &cancellables)
    }
    
    func logout() {
        let context = LAContext()
        localAuth.invalidateSession(newContext: context)
        self.allowAccess = false
    }
}

