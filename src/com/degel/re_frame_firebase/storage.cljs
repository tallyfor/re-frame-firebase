(ns com.degel.re-frame-firebase.storage
  (:require
    [clojure.spec.alpha :as s]
    [clojure.string :as str]
    [re-frame.core :as re-frame]
    [reagent.ratom :as ratom :refer [make-reaction]]
    [iron.re-utils :as re-utils :refer [<sub >evt event->fn sub->fn]]
    [iron.utils :as utils]
    [firebase.app :as firebase-app]
    [firebase.storage :as firebase-storage]
    [com.degel.re-frame-firebase.core :as core]
    [com.degel.re-frame-firebase.specs :as specs]
    [com.degel.re-frame-firebase.helpers :refer [promise-wrapper]]
    [fmnoise.flow :refer [Flow fail? then else]]
    [com.tallyfor.flow.fire.flow-functions :refer [flow-conform]]))


;;; 1. Create a root reference
;;; 2. Create reference to end object
;;; 3. Upload blob/file

(defn clj->StorageReference
  "Converts path, a string/keyword or seq of string/keywords, into a StorageReference"
  [path]
  (let [validated-path (flow-conform ::specs/path path "path" "clj->StorageReference")]
    #_(tap> {:clj->StorageReference/path           path
             :clj->StorageReference/validated-path validated-path})
    (->> validated-path
         (then (fn [validated-path]
                 (if (instance? js/firebase.storage.Reference validated-path)
                   validated-path
                   (.child
                     (.ref (js/firebase.storage))
                     (str/join "/" (clj->js validated-path)))))))))

(defn- putter
  [path blob]
  (->> (clj->StorageReference path)
       (then (fn [storage-reference]
               (.put storage-reference blob)))))

(defn put-effect [{:keys [path data on-success on-failure]}]
  (->> (promise-wrapper (putter path data) on-success on-failure)
       (else on-failure)))

(defn- deleter
  [path]
  (->> (clj->StorageReference path)
       (then (fn [storage-reference]
               (.delete storage-reference path)))))

(defn delete-effect [{:keys [path on-success on-failure]}]
  (->> (promise-wrapper (deleter path) on-success on-failure)
       (else on-failure)))
