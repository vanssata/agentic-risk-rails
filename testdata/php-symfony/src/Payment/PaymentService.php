<?php

namespace App\Payment;

final class PaymentService
{
    public function capture(int $amountCents): bool
    {
        return $amountCents > 0;
    }
}
