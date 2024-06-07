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
   [com.degel.re-frame-firebase.helpers :as helpers]
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
  (let [auth-instance (.auth js/firebase)  ; Get the Firebase auth instance
        current-user (.-currentUser auth-instance)]  ; Retrieve the current user
    
    (if current-user
      (-> (.linkWithPopup current-user provider)
          (.then (fn [result]
                   (let [user (.-user result)
                         user-data {:displayName (.-displayName user)
                                    :email (.-email user)
                                    :emailVerified (.-emailVerified user)
                                    :uid (.-uid user)
                                    :providerData (.-providerData user)}]
                    ;;  (js/console.log "Accounts linked" {:user-id (.-uid user)})
                     {:status :success :user user-data})))  ; Return success status and simplified user map
          (.catch (fn [error]
                    ;; (js/console.error "Linking error" {:error-msg (.-message error)})
                    {:status :failure :error-msg (.-message error)})))  ; Return failure status and error message
      (do
        (js/console.error "No current user logged in")
        {:status :failure :error-msg "No current user logged in"}))))

(defn unlink-a-user-account
  [provider-id]
  (let [auth-instance (.auth js/firebase)  ; Get the Firebase auth instance
        current-user (.-currentUser auth-instance)]  ; Retrieve the currently signed-in user

    (if current-user
      (-> (.unlink current-user provider-id)  ; Attempt to unlink the provider
          (.then (fn []
                  ;;  (js/console.log "Auth provider unlinked from account")  ; Log success message
                   {:status :success :message "Provider unlinked successfully" :provider-id provider-id}))
          (.catch (fn [error]
                    ;; (js/console.error "Failed to unlink account:" (.-message error))  ; Log error message
                    {:status :failure :message (.-message error)})))  ; Return error information
      (do
        (js/console.error "No current user logged in; cannot unlink accounts")
        {:status :failure :message "No current user logged in"}))))


(defn- maybe-link-with-credential
  [pending-credential user-credential]
  (when (and pending-credential user-credential)
    (when-let [firebase-user (.-user user-credential)]
      (-> firebase-user
          (.linkWithCredential pending-credential)
          (.catch (core/default-error-handler))))))

(defn- oauth-sign-in
  [auth-provider opts]
  (let [{:keys [sign-in-method scopes custom-parameters link-with-credential]
         :or {sign-in-method :redirect}} opts]

    (doseq [scope scopes]
      (.addScope auth-provider scope))

    (when custom-parameters
      (.setCustomParameters auth-provider (clj->js custom-parameters)))

    (if-let [sign-in (sign-in-fns sign-in-method)]
      (-> (js/firebase.auth)
          (sign-in auth-provider)
          (.then (partial maybe-link-with-credential link-with-credential))
          (.catch (core/default-error-handler)))
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
  [options]
  (if options
    (let [{:keys [provider-id on-success on-failure]} options
          provider (if provider-id
                     (js/firebase.auth.OAuthProvider. provider-id)
                     (throw (js/Error. "Provider ID is required")))
          link-promise (link-a-user-account provider)]
      (helpers/promise-wrapper link-promise on-success on-failure))
    (throw (js/Error. "Options map cannot be nil"))))

(defn unlink-oauth-provider
  [options]
  (if options
    (let [{:keys [provider-id on-success on-failure]} options
          unlink-promise (unlink-a-user-account provider-id)]
      (helpers/promise-wrapper unlink-promise on-success on-failure))
    (throw (js/Error. "Options map cannot be nil"))))

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
