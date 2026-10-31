<?php

namespace App\Tests\Payment;

use App\Payment\PaymentService;
use PHPUnit\Framework\TestCase;

final class PaymentServiceTest extends TestCase
{
    public function testCapturePositive(): void
    {
        self::assertTrue((new PaymentService())->capture(100));
    }
}
