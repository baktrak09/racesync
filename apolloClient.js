// src/apolloClient.js
import { ApolloClient, InMemoryCache, HttpLink } from '@apollo/client';

const client = new ApolloClient({
  link: new HttpLink({
    uri: 'https://your-store-name.myshopify.com/api/2023-04/graphql.json',
    headers: {
      'X-Shopify-Storefront-Access-Token': 'your-storefront-access-token',
    },
  }),
  cache: new InMemoryCache(),
});

export default client;
