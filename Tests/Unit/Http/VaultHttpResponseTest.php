<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use JsonException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Http\VaultHttpResponse;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

#[CoversClass(VaultHttpResponse::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultHttpResponseTest extends TestCase
{
    private const CONTENT_TYPE_JSON = 'application/json';

    private const CONTENT_TYPE_HTML = 'text/html';

    #[Test]
    public function getStatusCodeReturnsResponseStatusCode(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getStatusCode')->willReturn(200);

        $response = VaultHttpResponse::fromPsrResponse($psrResponse);

        self::assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function getReasonPhraseReturnsResponseReasonPhrase(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getReasonPhrase')->willReturn('OK');

        $response = VaultHttpResponse::fromPsrResponse($psrResponse);

        self::assertSame('OK', $response->getReasonPhrase());
    }

    #[Test]
    #[DataProvider('successfulStatusCodesProvider')]
    public function isSuccessfulReturnsTrueFor2xxCodes(int $statusCode): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getStatusCode')->willReturn($statusCode);

        $response = new VaultHttpResponse($psrResponse);

        self::assertTrue($response->isSuccessful());
    }

    public static function successfulStatusCodesProvider(): iterable
    {
        yield '200 OK' => [200];
        yield '201 Created' => [201];
        yield '204 No Content' => [204];
        yield '299 boundary' => [299];
    }

    /**
     * The first code of the NEXT class, and the last code of the previous one.
     * Each predicate is a half-open range, and asserting only the inside of it
     * cannot tell a correct upper bound from one that has swallowed the
     * neighbouring class — a 500 that also reports as a client error sends a
     * caller down the retry-is-pointless branch for an error that is worth
     * retrying.
     *
     * @return iterable<string, array{0: int, 1: string}>
     */
    public static function statusClassEdgeProvider(): iterable
    {
        yield '300 is not a success' => [300, 'isSuccessful'];
        yield '199 is not a success' => [199, 'isSuccessful'];
        yield '500 is not a client error' => [500, 'isClientError'];
        yield '399 is not a client error' => [399, 'isClientError'];
        yield '600 is not a server error' => [600, 'isServerError'];
        yield '499 is not a server error' => [499, 'isServerError'];
        yield '400 is not a redirect' => [400, 'isRedirect'];
        yield '299 is not a redirect' => [299, 'isRedirect'];
    }

    #[Test]
    #[DataProvider('statusClassEdgeProvider')]
    public function statusClassPredicatesExcludeTheNeighbouringClass(int $statusCode, string $predicate): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getStatusCode')->willReturn($statusCode);

        $response = new VaultHttpResponse($psrResponse);

        $actual = match ($predicate) {
            'isSuccessful' => $response->isSuccessful(),
            'isClientError' => $response->isClientError(),
            'isServerError' => $response->isServerError(),
            default => $response->isRedirect(),
        };

        self::assertFalse(
            $actual,
            \sprintf('%s() must not claim status %d.', $predicate, $statusCode),
        );
    }

    #[Test]
    public function isRedirectAcceptsTheFirstCodeOfItsClass(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getStatusCode')->willReturn(300);

        self::assertTrue((new VaultHttpResponse($psrResponse))->isRedirect());
    }

    #[Test]
    #[DataProvider('clientErrorStatusCodesProvider')]
    public function isClientErrorReturnsTrueFor4xxCodes(int $statusCode): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getStatusCode')->willReturn($statusCode);

        $response = new VaultHttpResponse($psrResponse);

        self::assertTrue($response->isClientError());
    }

    public static function clientErrorStatusCodesProvider(): iterable
    {
        yield '400 Bad Request' => [400];
        yield '401 Unauthorized' => [401];
        yield '403 Forbidden' => [403];
        yield '404 Not Found' => [404];
        yield '499 boundary' => [499];
    }

    #[Test]
    #[DataProvider('serverErrorStatusCodesProvider')]
    public function isServerErrorReturnsTrueFor5xxCodes(int $statusCode): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getStatusCode')->willReturn($statusCode);

        $response = new VaultHttpResponse($psrResponse);

        self::assertTrue($response->isServerError());
    }

    public static function serverErrorStatusCodesProvider(): iterable
    {
        yield '500 Internal Server Error' => [500];
        yield '502 Bad Gateway' => [502];
        yield '503 Service Unavailable' => [503];
        yield '599 boundary' => [599];
    }

    #[Test]
    public function isErrorReturnsTrueForClientAndServerErrors(): void
    {
        $clientError = $this->createMock(ResponseInterface::class);
        $clientError->method('getStatusCode')->willReturn(404);

        $serverError = $this->createMock(ResponseInterface::class);
        $serverError->method('getStatusCode')->willReturn(500);

        $success = $this->createMock(ResponseInterface::class);
        $success->method('getStatusCode')->willReturn(200);

        self::assertTrue((new VaultHttpResponse($clientError))->isError());
        self::assertTrue((new VaultHttpResponse($serverError))->isError());
        self::assertFalse((new VaultHttpResponse($success))->isError());
    }

    #[Test]
    public function isRedirectReturnsTrueFor3xxCodes(): void
    {
        $redirect = $this->createMock(ResponseInterface::class);
        $redirect->method('getStatusCode')->willReturn(302);

        $success = $this->createMock(ResponseInterface::class);
        $success->method('getStatusCode')->willReturn(200);

        self::assertTrue((new VaultHttpResponse($redirect))->isRedirect());
        self::assertFalse((new VaultHttpResponse($success))->isRedirect());
    }

    #[Test]
    public function getBodyReturnsStringBody(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('{"data": "test"}');

        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getBody')->willReturn($stream);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame('{"data": "test"}', $response->getBody());
    }

    #[Test]
    public function jsonDecodesBodyAsArray(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('{"name": "test", "value": 123}');

        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getBody')->willReturn($stream);

        $response = new VaultHttpResponse($psrResponse);

        $json = $response->json();

        self::assertIsArray($json);
        self::assertSame('test', $json['name']);
        self::assertSame(123, $json['value']);
    }

    #[Test]
    public function jsonDecodesBodyAsObject(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('{"name": "test"}');

        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getBody')->willReturn($stream);

        $response = new VaultHttpResponse($psrResponse);

        $json = $response->json(false);

        self::assertIsObject($json);
        self::assertSame('test', $json->name);
    }

    #[Test]
    public function jsonReturnsEmptyArrayForEmptyBody(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('');

        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getBody')->willReturn($stream);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame([], $response->json(true));
        self::assertNull($response->json(false));
    }

    #[Test]
    public function jsonThrowsExceptionForInvalidJson(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('not valid json');

        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getBody')->willReturn($stream);

        $response = new VaultHttpResponse($psrResponse);

        $this->expectException(JsonException::class);
        $response->json();
    }

    #[Test]
    public function jsonGetReturnsNestedValue(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('{"data": {"user": {"name": "John"}}}');

        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getBody')->willReturn($stream);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame('John', $response->jsonGet('data.user.name'));
        self::assertSame(['name' => 'John'], $response->jsonGet('data.user'));
        self::assertNull($response->jsonGet('data.user.email'));
        self::assertSame('default', $response->jsonGet('data.user.email', 'default'));
    }

    #[Test]
    public function jsonGetReturnsDefaultForInvalidJson(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('not valid json');

        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getBody')->willReturn($stream);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame('default', $response->jsonGet('key', 'default'));
    }

    #[Test]
    public function getHeaderReturnsFirstHeaderValue(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getHeader')->with('Content-Type')->willReturn([self::CONTENT_TYPE_JSON, 'charset=utf-8']);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame(self::CONTENT_TYPE_JSON, $response->getHeader('Content-Type'));
    }

    #[Test]
    public function getHeaderReturnsNullForMissingHeader(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getHeader')->with('X-Custom')->willReturn([]);

        $response = new VaultHttpResponse($psrResponse);

        self::assertNull($response->getHeader('X-Custom'));
    }

    #[Test]
    public function getHeaderValuesReturnsAllValues(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getHeader')->with('Accept')->willReturn([self::CONTENT_TYPE_JSON, self::CONTENT_TYPE_HTML]);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame([self::CONTENT_TYPE_JSON, self::CONTENT_TYPE_HTML], $response->getHeaderValues('Accept'));
    }

    /**
     * `application/json; charset=utf-8` splits into a media type that needs no
     * trimming, so it cannot show whether the trim happens. A header written
     * with the space before the separator can — and both spellings are legal
     * per RFC 9110, so a caller comparing the media type must get the same
     * answer for either.
     */
    #[Test]
    public function getContentTypeTrimsWhitespaceAroundTheMediaType(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse
            ->method('getHeader')
            ->willReturn([' application/json ; charset=utf-8']);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame(self::CONTENT_TYPE_JSON, $response->getContentType());
    }

    #[Test]
    public function getContentTypeStripsParameters(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getHeader')
            ->with('Content-Type')
            ->willReturn(['application/json; charset=utf-8']);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame(self::CONTENT_TYPE_JSON, $response->getContentType());
    }

    #[Test]
    public function isJsonReturnsTrueForJsonContentTypes(): void
    {
        $jsonResponse = $this->createMock(ResponseInterface::class);
        $jsonResponse->method('getHeader')
            ->with('Content-Type')
            ->willReturn([self::CONTENT_TYPE_JSON]);

        $apiResponse = $this->createMock(ResponseInterface::class);
        $apiResponse->method('getHeader')
            ->with('Content-Type')
            ->willReturn(['application/vnd.api+json']);

        $htmlResponse = $this->createMock(ResponseInterface::class);
        $htmlResponse->method('getHeader')
            ->with('Content-Type')
            ->willReturn([self::CONTENT_TYPE_HTML]);

        self::assertTrue((new VaultHttpResponse($jsonResponse))->isJson());
        self::assertTrue((new VaultHttpResponse($apiResponse))->isJson());
        self::assertFalse((new VaultHttpResponse($htmlResponse))->isJson());
    }

    #[Test]
    public function getContentLengthReturnsIntegerValue(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getHeader')
            ->with('Content-Length')
            ->willReturn(['1234']);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame(1234, $response->getContentLength());
    }

    #[Test]
    public function throwIfErrorThrowsForErrorStatus(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getStatusCode')->willReturn(404);
        $psrResponse->method('getReasonPhrase')->willReturn('Not Found');

        $response = new VaultHttpResponse($psrResponse);

        $this->expectException(VaultException::class);
        $this->expectExceptionMessageToContain('HTTP request failed with status 404: Not Found');

        $response->throwIfError();
    }

    #[Test]
    public function throwIfErrorReturnsSelfForSuccess(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getStatusCode')->willReturn(200);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame($response, $response->throwIfError());
    }

    #[Test]
    public function getPsrResponseReturnsUnderlyingResponse(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame($psrResponse, $response->getPsrResponse());
    }

    #[Test]
    public function getBodyStreamReturnsStreamInterface(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getBody')->willReturn($stream);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame($stream, $response->getBodyStream());
    }

    #[Test]
    public function getHeadersReturnsAllHeaders(): void
    {
        $headers = [
            'Content-Type' => [self::CONTENT_TYPE_JSON],
            'X-Custom' => ['value1', 'value2'],
        ];

        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getHeaders')->willReturn($headers);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame($headers, $response->getHeaders());
    }

    #[Test]
    public function hasHeaderReturnsTrueWhenExists(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('hasHeader')->with('Content-Type')->willReturn(true);

        $response = new VaultHttpResponse($psrResponse);

        self::assertTrue($response->hasHeader('Content-Type'));
    }

    #[Test]
    public function hasHeaderReturnsFalseWhenMissing(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('hasHeader')->with('X-Missing')->willReturn(false);

        $response = new VaultHttpResponse($psrResponse);

        self::assertFalse($response->hasHeader('X-Missing'));
    }

    #[Test]
    public function getContentTypeReturnsNullWhenMissing(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getHeader')->with('Content-Type')->willReturn([]);

        $response = new VaultHttpResponse($psrResponse);

        self::assertNull($response->getContentType());
    }

    #[Test]
    public function getContentLengthReturnsNullWhenMissing(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getHeader')->with('Content-Length')->willReturn([]);

        $response = new VaultHttpResponse($psrResponse);

        self::assertNull($response->getContentLength());
    }

    #[Test]
    public function isJsonReturnsFalseWhenNoContentType(): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getHeader')->with('Content-Type')->willReturn([]);

        $response = new VaultHttpResponse($psrResponse);

        self::assertFalse($response->isJson());
    }

    #[Test]
    #[DataProvider('nonSuccessfulStatusCodesProvider')]
    public function isSuccessfulReturnsFalseForNon2xxCodes(int $statusCode): void
    {
        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getStatusCode')->willReturn($statusCode);

        $response = new VaultHttpResponse($psrResponse);

        self::assertFalse($response->isSuccessful());
    }

    public static function nonSuccessfulStatusCodesProvider(): iterable
    {
        yield '199 below range' => [199];
        yield '300 redirect' => [300];
        yield '404 client error' => [404];
        yield '500 server error' => [500];
    }

    #[Test]
    public function jsonGetReturnsDefaultForObjectModeJson(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('{"key": "value"}');

        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getBody')->willReturn($stream);

        $response = new VaultHttpResponse($psrResponse);

        // jsonGet works in associative array mode internally
        self::assertSame('value', $response->jsonGet('key'));
    }

    #[Test]
    public function jsonGetHandlesMissingIntermediateKey(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('{"a": {"b": "value"}}');

        $psrResponse = $this->createMock(ResponseInterface::class);
        $psrResponse->method('getBody')->willReturn($stream);

        $response = new VaultHttpResponse($psrResponse);

        self::assertSame('default', $response->jsonGet('a.c.d', 'default'));
    }
}
