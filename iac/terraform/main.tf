resource "kubernetes_pod" "IQBNetApp" {
  metadata {
    name = "IQBNetApp"
    namespace = "evolved5g"
    labels = {
      app = "IQBNetApp"
    }
  }

  spec {
    container {
      image = "dockerhub.hi.inet/evolved-5g/dummy-netapp:latest"
      name  = "dummy-netapp"
    }
  }
}

resource "kubernetes_service" "IQBNetApp_service" {
  metadata {
    name = "IQBNetApp"
    namespace = "evolved5g"
  }
  spec {
    selector = {
      app = kubernetes_pod.IQBNetApp.metadata.0.labels.app
    }
    port {
      port = 5000
      target_port = 5000
    }
  }
}
