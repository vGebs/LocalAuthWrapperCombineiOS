//
//  File.swift
//  
//
//  Created by Vaughn on 2023-01-19.
//

import SwiftUI

@available(iOS 13.0.0, *)
struct ContentView: View {
    @ObservedObject var appState = AppState.shared
    
    var body: some View {
        ZStack {
            if appState.allowAccess {
                VStack {
                    Text("Successful login").padding()
                    Button(action: {
                        appState.logout()
                    }) {
                        Text("logout")
                    }
                }
            } else {
                Button(action: {
                    appState.login()
                }) {
                    Text("login")
                }
            }
        }
    }
}
