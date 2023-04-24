<template>
  <v-col
    lg="4"
    md="6"
    sm="8"
    offset-lg="4"
    offset-md="3"
    offset-sm="2"
  >
    <v-card :loading="loading">
      <v-card-title class="d-flex justify-center">
        <p>Connexion avec Cloudflare Access</p>
      </v-card-title>
      <v-card-text>
        Merci de patienter pendant l'authentification automatique de votre session en validant votre identité avec Cloudflare Access.
      </v-card-text>
    </v-card>
  </v-col>
</template>

<script>
export default {
  props: {
    config: { type: Object, default: () => {} }
  },
  data () {
    return {
      loading: false
    }
  },
  mounted () {
    if (this.hasAuth()) {
      this.$router.push({ name: 'Servers' })
    } else {
      this.submit()
    }
  },
  methods: {
    async submit () {
      this.loading = true
      const cloudflareAuthorization = this.$api.getCloudflareAuthorization()
      if (await this.$api.loginCloudflare(cloudflareAuthorization) === true) {
        if (this.hasScope('servers.view') || this.isAdmin()) {
          await this.$router.push({ name: 'Servers' })
        } else {
          await this.$router.push({ name: 'Account' })
        }
      }
      this.loading = false
    }
  }
}
</script>
