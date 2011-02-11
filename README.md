# SAuth

The goal of this authorization scheme is to provide a way for a web-apps
to access a web-service and interact with it based on the needs of the
current user of the web-app, without the web-service having to know about
the current user in any way.

It does this by allowing the web-app to get tokens from the web-service
which grant a specific amount of access, for a specific amount of time,
for a specific set of capabilities.

This is heavily based on the ideas found in OAuth and OAuth2, but our
aim is to provide a much tighter focus on just web-app/web-service
interplay.

## Basic Flow

- The user logs into the web-app, knowing nothing more then that. They are
  authenticated within that application and all is well.

- The web-app itself now needs to ask the web-service for a token, or
  loads a pre-existing token somehow (in which case you would skip the
  next several steps).

- The web-app and the web-service have a pre-arranged relationship and the
  web-app has been given a key from the web-service.

- The web-app then takes the key, queries the local user info and builds an
  access-request.

- The access-request is then combined with a timestamp and the key to produce
  an HMAC.

- The access-request, the timestamp and the HMAC are all sent to the web-service.

- The web-service then checks the access-request, timestamp and HMAC using
  it's copy of the key (located using the 'uid' field in the access-request)

- If the key exists in the web-service's key-store, then it examines the list
  of capabilities in the access-request.

- If the access-request is valid then the web-service creates a token and an
  access-grant to be given back to the web-app.

- The web-service then stores the token and access-grant in the token store.

- The web-service sends the web-app back the access-grant.

- The web-app also then acuires a nonce.

- On each request to the web-service from the web-app, the web-app must include
  the token and the a hash digest of (token + the key + the current nonce) and
  the current nonce.

- On each response from the web-service, a new nonce is sent to be used for
  the next request.

## Terms

*user* -
the end-point, usually a human being

*web-app* -
a client of the web service

*web-service* -
another end-point, usually the owner of some resources

*key* -
a UUID given to a web-app by a web-service to confirm their relationship with one
another. The key is their shared secret. A web-app will typically only have one
key, while a web-service will have given out many keys.

*key-store* -
a mapping held by the web-service that maps the keys to a set of capabilities. Those
capabilities might look something like:

    {
        // the UID, which can be a URL or
        // something else which will work
        uid : http://my.webapp.com/,
        // list of roles that are allowed
        allowed : [
            // ex:
            // - read
            // - edit
            // - delete
            // - create
            // the combination of which determine
            // what access is allowed
        ],
        // does this key allow tokens to
        // be refreshed? Or is this a one
        // time access
        allow_refresh : {true,false},
        // the date at which this key expires
        expires : <date>,
        // the maximun length of a tokens life
        token_max_lifespan : <duration>
    }

*access-request* -
a set of data passed from the web-app to the web-service which contains information about
what it is they want to do. An example might be:

    {
        uid : http://my.webapp.com/, // they key identifier so that the service knows
                                     // what to lookup
        access_for : [ read, edit ], // asking for access to read and edit resources
        token_lifespan : <duration>  // requested timespan for the token (optional: if
                                     // not supplied, max will be given)
    }

*access-grant* -
a modified version of the access-request which tells the app what access is being given.
An example might be:

    {
        token : <session-token>,   // the token which is then expected to be sent with
                                   // each request
        access_to : [ read ],      // the capabilities granted (usually the same as
                                   // access-request)
        timeout : <duration>       // the timespan in which the token is valid
        can_refresh : {true,false} // lets them know if they can expect to refresh the token
                                   // without re-auth
    }

*token* -
a UUID given by the web-service in response to an access-request. It represents the granting
of an access-request.

*token-store* -
a mapping held by the web-service that maps the tokens to a specific access-grant.

## Installation

To install this module type the following:

    perl Makefile.PL
    make
    make test
    make install

## Dependencies

This module requires these other modules and libraries:

    Moose
    MooseX::Params::Validate
    MooseX::Types::Path::Class
    MooseX::NonMoose

    Plack
    Plack::App::Path::Router::PSGI
    Path::Router
    HTTP::Throwable
    HTTP::Request::Common

    DateTime
    DateTime::Duration
    DateTime::Format::RFC3339

    Digest
    Digest::HMAC
    Digest::SHA1
    Crypt::Random::Source
    Data::UUID

    JSON::XS
    MIME::Base64

    List::AllUtils
    Sub::Exporter
    Try::Tiny
    Devel::PartialDump

    Test::More
    Test::Moose
    Test::Fatal

## Copyright and License

Copyright (C) 2011 Infinity Interactive, Inc.

(http://www.iinteractive.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.









