;;; Author: David Goldfarb (deg@degel.com)
;;; Copyright (c) 2017, David Goldfarb

(ns com.degel.re-frame-firebase.auth
  (:require-macros [reagent.ratom :refer [reaction]])
  (:require
   [clojure.spec.alpha :as s]
   [re-frame.core :as re-frame]
   [iron.re-utils :refer [>evt]]
   [firebase.app :as firebase-app]
   [firebase.auth :as firebase-auth]
   [com.degel.re-frame-firebase.core :as core]))


(defn- user
  "Extract interesting details from the Firebase JS user object."
  [firebase-user]
  (when firebase-user
    {:uid           (.-uid firebase-user)
     :provider-data (.-providerData firebase-user)
     :display-name  (.-displayName firebase-user)
     :photo-url     (.-photoURL firebase-user)
     :email         (let [provider-data (.-providerData firebase-user)]
                      (when-not (empty? provider-data)
                        (-> provider-data first .-email)))}))

(defn- set-user
  [firebase-user]
  (-> firebase-user
      (user)
      (core/set-current-user)))

(defn- init-auth []
  (.onAuthStateChanged
   (js/firebase.auth)
   set-user
   (core/default-error-handler))

  (-> (js/firebase.auth)
      (.getRedirectResult)
      (.then (fn on-user-credential [user-credential]
               (-> user-credential
                   (.-user)
                   set-user)))
      (.catch (core/default-error-handler))))

(def ^:private sign-in-fns
  {:popup (memfn signInWithPopup auth-provider)
   :redirect (memfn signInWithRedirect auth-provider)})

(defn link-a-user-account [provider]
  (let [auth-instance (.auth js/firebase)  ; Correct invocation of the auth method
        current-user (.-currentUser auth-instance)]  ; Get the current user from the auth instance
    (if current-user
      (-> (.linkWithPopup current-user provider)
          (.then (fn [result]
                   (let [credential (.-credential result)
                         user (.-user result)]
                     (js/console.log "Accounts linked successfully" {:user user :credential credential})
                     {:status :success :user user :credential credential})))
          (.catch (fn [error]
                    (js/console.error "Failed to link accounts" {:message (.-message error)})
                    (throw (js/Error. (.-message error))))))
      (do
        (js/console.log "No current user logged in; cannot link accounts")
        (throw (js/Error. "No current user logged in"))))))  

(defn unlink-a-user-account
  [provider-id]
  (let [auth-instance (.auth js/firebase)  ; Get the Firebase auth instance
        current-user (.-currentUser auth-instance)]  ; Retrieve the currently signed-in user
    (js/console.log "Firebase Auth Instance:" auth-instance)  ; Log the auth instance for debugging
    (js/console.log "Current User:" current-user)  ; Log the current user for debugging
    (js/console.log "Provider ID to Unlink:" provider-id)  ; Log the provider ID being passed

    (if current-user
      (-> (.unlink current-user provider-id)  ; Attempt to unlink the provider
          (.then (fn []
                   (js/console.log "Auth provider unlinked from account")  ; Log success message
                   {:status :success :message "Provider unlinked successfully"}))
          (.catch (fn [error]
                    (js/console.error "Failed to unlink account:" (.-message error))  ; Log error message
                    {:status :failure :message (.-message error)})))  ; Return error information
      (do
        (js/console.error "No current user logged in; cannot unlink accounts")  ; Log error if no user is signed in
        {:status :failure :message "No current user logged in"}))))





(defn- oauth-sign-in
  [auth-provider opts]
  (let [{:keys [sign-in-method scopes custom-parameters]
         :or {sign-in-method :redirect}} opts]

    (doseq [scope scopes]
      (.addScope auth-provider scope))

    (when custom-parameters
      (.setCustomParameters auth-provider (clj->js custom-parameters)))

    (if-let [sign-in (sign-in-fns sign-in-method)]
      (-> (js/firebase.auth)
          (sign-in auth-provider)
          (.then (fn [result]
                   {:status :success
                    :result result}))
          (.catch 
           (fn [error]
                    {:status :error
                     :error error
                     :message (.message error)
                     :code (.-code error)}) 
                  (core/default-error-handler)))
      (>evt [(core/default-error-handler)
             (js/Error. (str "Unsupported sign-in-method: " sign-in-method ". Either :redirect or :popup are supported."))]))))


(defn google-sign-in
  [opts]
  ;; TODO: use Credential for mobile. 
  (oauth-sign-in (js/firebase.auth.GoogleAuthProvider.) opts))

(defn ocid-xero-sign-in
  [opts]
  (let [provider (js/firebase.auth.OAuthProvider. "oidc.xero")]
    (.addScope provider "profile")
    (.addScope provider "email")
    (oauth-sign-in provider opts)))

(defn link-oauth-provider
  [provider-id]
  (let [provider (js/firebase.auth.OAuthProvider. provider-id)]
    ;; Todo assuming diff providers will need diff scopes, may need to adjust accordingly
    (link-a-user-account provider)))

(defn unlink-oauth-provider
  [provider-id]
  (unlink-a-user-account provider-id))

(defn facebook-sign-in
  [opts]
  (oauth-sign-in (js/firebase.auth.FacebookAuthProvider.) opts))


(defn twitter-sign-in
  [opts]
  (oauth-sign-in (js/firebase.auth.TwitterAuthProvider.) opts))


(defn github-sign-in
  [opts]
  (oauth-sign-in (js/firebase.auth.GithubAuthProvider.) opts))


(defn microsoft-sign-in
  [opts]
  (oauth-sign-in (js/firebase.auth.OAuthProvider. "microsoft.com") opts))

(defn email-sign-in [{:keys [email password]}]
  (-> (js/firebase.auth)
      (.signInWithEmailAndPassword email password)
      (.then set-user)
      (.catch (core/default-error-handler))))


(defn email-create-user [{:keys [email password]}]
  (-> (js/firebase.auth)
      (.createUserWithEmailAndPassword email password)
      (.then set-user)
      (.catch (core/default-error-handler))))


(defn anonymous-sign-in [opts]
  (-> (js/firebase.auth)
      (.signInAnonymously)
      (.then set-user)
      (.catch (core/default-error-handler))))


(defn custom-token-sign-in [{:keys [token]}]
  (-> (js/firebase.auth)
      (.signInWithCustomToken token)
      (.then set-user)
      (.catch (core/default-error-handler))))


(defn init-recaptcha [{:keys [on-solve container-id]}]
  (let [recaptcha (js/firebase.auth.RecaptchaVerifier.
                   container-id
                   (clj->js {:size     "invisible"
                             :callback #(re-frame/dispatch on-solve)}))]
    (swap! core/firebase-state assoc
           :recaptcha-verifier recaptcha)))


(defn phone-number-sign-in [{:keys [phone-number on-send]}]
  (if-let [verifier (:recaptcha-verifier @core/firebase-state)]
    (-> (js/firebase.auth)
        (.signInWithPhoneNumber phone-number verifier)
        (.then (fn [confirmation]
                 (when on-send
                   (re-frame/dispatch on-send))
                 (swap! core/firebase-state assoc
                        :recaptcha-confirmation-result confirmation)))
        (.catch (core/default-error-handler)))
    (.warn js/console "Initialise reCaptcha first")))


(defn phone-number-confirm-code [{:keys [code]}]
  (if-let [confirmation (:recaptcha-confirmation-result @core/firebase-state)]
    (-> confirmation
        (.confirm code)
        (.then set-user)
        (.catch (core/default-error-handler)))
    (.warn js/console "reCaptcha confirmation missing")))


(defn sign-out []
  (-> (js/firebase.auth)
      (.signOut)
      (.catch (core/default-error-handler))))
